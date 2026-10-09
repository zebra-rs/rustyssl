//! `OSSL_PARAM_dup`, `OSSL_PARAM_merge`, and `OSSL_PARAM_free` (`crypto/params_dup.c`).
//!
//! A duplicate is one block, as in OpenSSL: the array, then each parameter's data in 8-octet
//! units (a pointer for the `_ptr` types, one more octet for a UTF-8 string's NUL). Data that
//! lies in the secure heap is copied to a second block there, which the terminating parameter
//! records (type `OSSL_PARAM_ALLOCATED_END`, the block and its size) for `OSSL_PARAM_free`.

use core::cmp::Ordering;
use core::ffi::{CStr, c_void};
use core::ptr;

use rustyssl_abi::{
    CRYPTO_R_NO_PARAMS_TO_MERGE, ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, OSSL_PARAM,
};
use rustyssl_crypto::params::{OCTET_PTR, UTF8_PTR, UTF8_STRING, strcasecmp};

use crate::err;
use crate::ffi::ffi_export;
use crate::{mem, secure};

/// `OSSL_PARAM_ALLOCATED_END` (`crypto/params_dup.c`): the type of the terminator of an
/// array that owns a secure-heap block.
pub(super) const ALLOCATED_END: u32 = 127;

/// `OSSL_PARAM_ALIGN_SIZE`: the size of the union of a `double`, an `intmax_t`, and a pointer.
pub(super) const ALIGN: usize = 8;

/// `OSSL_PARAM_MERGE_LIST_MAX`: the parameters taken from each array to merge.
const MERGE_LIST_MAX: usize = 128;

/// `ossl_param_bytes_to_blocks`: the units `bytes` take.
pub(super) fn blocks(bytes: usize) -> Option<usize> {
    Some(bytes.checked_add(ALIGN - 1)? / ALIGN)
}

/// The octets of an array of `n` parameters, in units.
pub(super) fn array_blocks(n: usize) -> Option<usize> {
    blocks(n.checked_mul(size_of::<OSSL_PARAM>())?)
}

/// The parameters of the array at `p`, up to its terminator.
///
/// # Safety
/// `p` is an array ended by a parameter with a NULL key, outliving `'a`.
unsafe fn params<'a>(p: *const OSSL_PARAM) -> impl Iterator<Item = &'a OSSL_PARAM> {
    let mut at = p;
    core::iter::from_fn(move || {
        // SAFETY: the caller's guarantee: the array goes on to its terminator, and `at` stops
        // there.
        let param = unsafe { &*at };
        if param.key.is_null() {
            return None;
        }
        at = at.wrapping_add(1);
        Some(param)
    })
}

/// The octets a parameter's copy takes, and how many of them come from its data.
fn copy_size(p: &OSSL_PARAM) -> (usize, usize) {
    let copied = if p.data_type == OCTET_PTR || p.data_type == UTF8_PTR {
        size_of::<*const c_void>()
    } else {
        p.data_size
    };
    let room = copied.saturating_add(usize::from(p.data_type == UTF8_STRING));
    (room, copied)
}

/// The terminator of an array owning the secure block `data` of `size` octets (NULL and 0 for
/// none).
pub(super) fn allocated_end(data: *mut c_void, size: usize) -> OSSL_PARAM {
    OSSL_PARAM {
        key: ptr::null(),
        data_type: ALLOCATED_END,
        data,
        data_size: size,
        return_size: 0,
    }
}

ffi_export! {
    /// A copy of the array `src` and all its data, in one block for `OSSL_PARAM_free` (data in
    /// the secure heap is copied there). NULL on failure.
    ///
    /// Unlike OpenSSL, a parameter with a NULL data pointer is copied with zeroed data rather
    /// than crashing the copy (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `src` is NULL or an array ended by a parameter with a NULL key, whose data is NULL or
    /// holds `data_size` octets (a pointer, for the `_ptr` types).
    pub unsafe extern "C" fn OSSL_PARAM_dup(src: *const OSSL_PARAM) -> *mut OSSL_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if src.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OSSL_PARAM_dup");
            return ptr::null_mut();
        }
        // First pass: the parameters and the units of each block.
        let mut count = 0usize;
        let mut units = [0usize; 2];
        // SAFETY: the caller's guarantee.
        for p in unsafe { params(src) } {
            let secure = usize::from(secure::in_arena(p.data));
            let Some(n) = blocks(copy_size(p).0) else { return ptr::null_mut() };
            let Some(total) = units.get_mut(secure) else { return ptr::null_mut() };
            let Some(sum) = total.checked_add(n) else { return ptr::null_mut() };
            *total = sum;
            count = count.saturating_add(1);
        }
        let [public, private] = units;
        let Some(head) = count.checked_add(1).and_then(array_blocks) else {
            return ptr::null_mut();
        };
        let Some(size) = head.checked_add(public).and_then(|n| n.checked_mul(ALIGN)) else {
            return ptr::null_mut();
        };
        let Some(secure_size) = private.checked_mul(ALIGN) else { return ptr::null_mut() };
        let block = mem::alloc_zeroed(size).cast::<u8>();
        if block.is_null() {
            return ptr::null_mut();
        }
        let mut secure_block = ptr::null_mut::<u8>();
        if secure_size > 0 {
            secure_block = secure::alloc_zeroed(secure_size).cast();
            if secure_block.is_null() {
                // SAFETY: the block was just allocated and nothing points into it.
                unsafe { mem::release(block.cast()) };
                return ptr::null_mut();
            }
        }
        // Second pass: the copies.
        let array = block.cast::<OSSL_PARAM>();
        let mut cursors = [block.wrapping_add(head * ALIGN), secure_block];
        let mut last = array;
        // SAFETY: the caller's guarantee, as in the first pass.
        for p in unsafe { params(src) } {
            let secure = usize::from(secure::in_arena(p.data));
            let (room, copied) = copy_size(p);
            let Some(cursor) = cursors.get_mut(secure) else { break };
            let to = *cursor;
            if !p.data.is_null() && copied > 0 {
                // SAFETY: the data holds `copied` octets (the caller's guarantee), and `to`
                // has `room` of the block counted for it in the first pass.
                unsafe { ptr::copy_nonoverlapping(p.data.cast::<u8>(), to, copied) };
            }
            let copy = OSSL_PARAM { data: to.cast(), ..*p };
            // SAFETY: the array has room for `count` parameters and the terminator.
            unsafe { last.write(copy) };
            last = last.wrapping_add(1);
            *cursor = to.wrapping_add(blocks(room).unwrap_or(0) * ALIGN);
        }
        // SAFETY: the terminator's place in the array.
        unsafe { last.write(allocated_end(secure_block.cast(), secure_size)) };
        array
    }
}

ffi_export! {
    /// A new array of the parameters of `p1` and `p2` (shallow copies, at most 128 from each)
    /// sorted by key without case, where a key in both takes `p2`'s. Free it with
    /// `OSSL_PARAM_free`.
    ///
    /// # Safety
    /// Each of `p1` and `p2` is NULL or an array ended by a parameter with a NULL key, whose
    /// keys are strings.
    pub unsafe extern "C" fn OSSL_PARAM_merge(p1: *const OSSL_PARAM, p2: *const OSSL_PARAM) -> *mut OSSL_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_merge";
        if p1.is_null() && p2.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, name);
            return ptr::null_mut();
        }
        let list = |p: *const OSSL_PARAM| -> Vec<&OSSL_PARAM> {
            if p.is_null() {
                return Vec::new();
            }
            // SAFETY: the caller's guarantee.
            let mut v: Vec<_> = unsafe { params(p) }.take(MERGE_LIST_MAX).collect();
            v.sort_by(|a, b| compare(a, b));
            v
        };
        let (list1, list2) = (list(p1), list(p2));
        if list1.is_empty() && list2.is_empty() {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_NO_PARAMS_TO_MERGE, name);
            return ptr::null_mut();
        }
        let mut merged = Vec::with_capacity(list1.len() + list2.len());
        let (mut a, mut b) = (list1.into_iter().peekable(), list2.into_iter().peekable());
        loop {
            let next = match (a.peek(), b.peek()) {
                (None, None) => break,
                (Some(_), None) => a.next(),
                (None, Some(_)) => b.next(),
                (Some(x), Some(y)) => match compare(x, y) {
                    Ordering::Equal => {
                        a.next();
                        b.next()
                    }
                    Ordering::Greater => b.next(),
                    Ordering::Less => a.next(),
                },
            };
            merged.extend(next.copied());
        }
        let Some(size) = merged.len().checked_add(1).and_then(|n| n.checked_mul(size_of::<OSSL_PARAM>())) else {
            return ptr::null_mut();
        };
        let array = mem::alloc_zeroed(size).cast::<OSSL_PARAM>();
        if array.is_null() {
            return ptr::null_mut();
        }
        for (i, p) in merged.into_iter().enumerate() {
            // SAFETY: the array has room for every merged parameter and a zeroed terminator.
            unsafe { array.add(i).write(p) };
        }
        array
    }
}

/// Orders two parameters by key, as `OPENSSL_strcasecmp`.
fn compare(a: &OSSL_PARAM, b: &OSSL_PARAM) -> Ordering {
    // SAFETY: both come from arrays whose keys are strings (the merge's caller guarantees it).
    let ka = unsafe { CStr::from_ptr(a.key) };
    // SAFETY: as above.
    let kb = unsafe { CStr::from_ptr(b.key) };
    strcasecmp(ka.to_bytes(), kb.to_bytes())
}

ffi_export! {
    /// Frees an array from `OSSL_PARAM_dup`, `OSSL_PARAM_merge`, or `OSSL_PARAM_BLD_to_param`,
    /// with the secure block its terminator records; NULL does nothing.
    ///
    /// # Safety
    /// `params` is NULL or such an array, not used afterwards.
    pub unsafe extern "C" fn OSSL_PARAM_free(params: *mut OSSL_PARAM)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if params.is_null() {
            return;
        }
        let mut at = params;
        // SAFETY: the caller's guarantee: the array goes on to its terminator.
        while !unsafe { (*at).key }.is_null() {
            at = at.wrapping_add(1);
        }
        // SAFETY: `at` is the terminator.
        let end = unsafe { &*at };
        if end.data_type == ALLOCATED_END {
            // SAFETY: the terminator records the array's secure block (or NULL).
            unsafe { secure::release_clean(end.data, end.data_size) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(params.cast()) };
    }
}
