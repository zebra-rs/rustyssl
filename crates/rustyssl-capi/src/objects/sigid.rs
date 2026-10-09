//! Signature algorithms and the digest and public-key algorithms they combine
//! (`OBJ_find_sigid_algs(3)`, `OBJ_find_sigid_by_algs`, `OBJ_add_sigid`, `OBJ_sigid_free`).
//!
//! The built-in table comes first (`rustyssl_asn1::objects`). Algorithms applications add are
//! kept, as in OpenSSL, on two stacks sorted with the C library's `qsort`: one by signature, one
//! by digest and key, whose comparator lets an added algorithm without a digest match any
//! digest. The stacks' searches are OpenSSL's, so which of several matches is found is too.

use core::ffi::{c_int, c_void};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{ERR_LIB_OBJ, NID_undef, OPENSSL_STACK};
use rustyssl_asn1::objects as table;

use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_sort, OPENSSL_sk_value,
};

/// OpenSSL's `nid_triple`.
#[repr(C)]
struct Triple {
    sign_id: c_int,
    hash_id: c_int,
    pkey_id: c_int,
}

/// The stacks of added algorithms (`sig_app` and `sigx_app`), both holding the same triples.
struct Added {
    by_signature: *mut OPENSSL_STACK,
    by_algorithms: *mut OPENSSL_STACK,
}

// SAFETY: the stacks are only used under the mutex.
unsafe impl Send for Added {}

static ADDED: Mutex<Added> = Mutex::new(Added {
    by_signature: ptr::null_mut(),
    by_algorithms: ptr::null_mut(),
});

/// The triple an element pointer of the stacks points to.
///
/// # Safety
/// `element` points to a stack slot holding a live triple.
unsafe fn triple<'a>(element: *const c_void) -> &'a Triple {
    // SAFETY: the caller's guarantee.
    let triple = unsafe { *element.cast::<*const Triple>() };
    // SAFETY: as above.
    unsafe { &*triple }
}

ffi_callback! {
    /// `sig_sk_cmp`: by signature.
    ///
    /// # Safety
    /// Both point to stack slots holding live triples.
    pub(crate) unsafe extern "C" fn by_signature(a: *const c_void, b: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { triple(a) };
        // SAFETY: as above.
        let b = unsafe { triple(b) };
        a.sign_id.wrapping_sub(b.sign_id)
    }
}

ffi_callback! {
    /// `sigx_cmp`: by digest, then key; an element without a digest (`b`) takes any.
    ///
    /// # Safety
    /// Both point to stack slots holding live triples.
    pub(crate) unsafe extern "C" fn by_algorithms(a: *const c_void, b: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { triple(a) };
        // SAFETY: as above.
        let b = unsafe { triple(b) };
        let difference = a.hash_id.wrapping_sub(b.hash_id);
        if difference != 0 && b.hash_id != NID_undef {
            return difference;
        }
        a.pkey_id.wrapping_sub(b.pkey_id)
    }
}

ffi_callback! {
    /// Frees a triple.
    ///
    /// # Safety
    /// `triple` came from this allocator.
    pub(crate) unsafe extern "C" fn free_triple(triple: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(triple) }
    }
}

/// The added triple in `stack` that its comparator finds equal to `key`.
///
/// # Safety
/// `stack` is NULL or one of the stacks, used under the mutex.
unsafe fn find(stack: *mut OPENSSL_STACK, key: &Triple) -> Option<&Triple> {
    if stack.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee; the comparators read the key.
    let index = unsafe { OPENSSL_sk_find(stack, ptr::from_ref(key).cast()) };
    if index < 0 {
        return None;
    }
    // SAFETY: as above.
    let element = unsafe { OPENSSL_sk_value(stack, index) };
    // SAFETY: the stacks hold live triples.
    (!element.is_null()).then(|| unsafe { &*element.cast::<Triple>() })
}

/// `ossl_obj_find_sigid_algs`: the digest and key of `signature`, built in or added.
fn algorithms_of(added: &Added, signature: c_int) -> Option<(c_int, c_int)> {
    if signature == NID_undef {
        return None;
    }
    if let Some(row) = table::signature_by_id(signature) {
        return Some((row.digest, row.pkey));
    }
    let key = Triple {
        sign_id: signature,
        hash_id: NID_undef,
        pkey_id: NID_undef,
    };
    // SAFETY: the stack, under the mutex.
    unsafe { find(added.by_signature, &key) }.map(|t| (t.hash_id, t.pkey_id))
}

ffi_export! {
    /// The digest (into `*pdig_nid`) and public-key algorithm (into `*ppkey_nid`) of signature
    /// algorithm `signid`; either pointer may be NULL. 0 if `signid` isn't known.
    ///
    /// # Safety
    /// `pdig_nid` and `ppkey_nid` are NULL or valid for writes.
    pub unsafe extern "C" fn OBJ_find_sigid_algs(signid: c_int, pdig_nid: *mut c_int, ppkey_nid: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        let found = {
            let added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
            algorithms_of(&added, signid)
        };
        let Some((digest, pkey)) = found else {
            return 0;
        };
        if !pdig_nid.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { pdig_nid.write(digest) };
        }
        if !ppkey_nid.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { ppkey_nid.write(pkey) };
        }
        1
    }
}

ffi_export! {
    /// The signature algorithm (into `*psignid`, if not NULL) that combines digest `dig_nid` and
    /// public-key algorithm `pkey_nid`. 0 if there's none, or `pkey_nid` is `NID_undef`.
    ///
    /// # Safety
    /// `psignid` is NULL or valid for a write.
    pub unsafe extern "C" fn OBJ_find_sigid_by_algs(psignid: *mut c_int, dig_nid: c_int, pkey_nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        if pkey_nid == NID_undef {
            return 0;
        }
        let found = table::signature_by_algorithms(dig_nid, pkey_nid).or_else(|| {
            let added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
            let key = Triple { sign_id: NID_undef, hash_id: dig_nid, pkey_id: pkey_nid };
            // SAFETY: the stack, under the mutex.
            unsafe { find(added.by_algorithms, &key) }.map(|t| t.sign_id)
        });
        let Some(signature) = found else {
            return 0;
        };
        if !psignid.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { psignid.write(signature) };
        }
        1
    }
}

ffi_export! {
    /// Adds signature algorithm `signid` combining `dig_id` (which may be `NID_undef`) and
    /// `pkey_id`. Returns 1, or for a known `signid` whether it combines the same algorithms; 0
    /// if `signid` or `pkey_id` is `NID_undef`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_add_sigid(signid: c_int, dig_id: c_int, pkey_id: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        if signid == NID_undef || pkey_id == NID_undef {
            return 0;
        }
        let triple: *mut Triple = mem::alloc(size_of::<Triple>()).cast();
        if triple.is_null() {
            return 0;
        }
        // SAFETY: just allocated, big enough.
        unsafe { triple.write(Triple { sign_id: signid, hash_id: dig_id, pkey_id }) };
        let mut added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((digest, pkey)) = algorithms_of(&added, signid) {
            // SAFETY: not shared.
            unsafe { mem::release(triple.cast()) };
            return c_int::from(digest == dig_id && pkey == pkey_id);
        }
        let Added { by_signature: sig, by_algorithms: sigx } = &mut *added;
        for (stack, compare) in [
            (sig, by_signature as unsafe extern "C" fn(_, _) -> _),
            (sigx, by_algorithms),
        ] {
            if stack.is_null() {
                // SAFETY: a comparator for stacks of triples.
                *stack = unsafe { OPENSSL_sk_new(Some(compare)) };
                if stack.is_null() {
                    // SAFETY: not shared.
                    unsafe { mem::release(triple.cast()) };
                    return 0;
                }
            }
        }
        // SAFETY: the stack, under the mutex.
        if unsafe { OPENSSL_sk_push(added.by_signature, triple.cast()) } == 0 {
            // SAFETY: not shared.
            unsafe { mem::release(triple.cast()) };
            return 0;
        }
        // SAFETY: as above. On failure the triple stays on the first stack, as in OpenSSL.
        if unsafe { OPENSSL_sk_push(added.by_algorithms, triple.cast()) } == 0 {
            return 0;
        }
        // SAFETY: the stacks, under the mutex.
        unsafe { OPENSSL_sk_sort(added.by_signature) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_sort(added.by_algorithms) };
        1
    }
}

ffi_export! {
    /// Forgets the added signature algorithms.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_sigid_free()
    where failure = (), library = ERR_LIB_OBJ
    {
        let mut added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the stacks, under the mutex; the first owns the triples.
        unsafe { OPENSSL_sk_pop_free(added.by_signature, Some(free_triple)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(added.by_algorithms) };
        added.by_signature = ptr::null_mut();
        added.by_algorithms = ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searches_after_freeing_find_nothing() {
        // SAFETY: no preconditions.
        assert_eq!(unsafe { OBJ_add_sigid(6001, 672, 1087) }, 1);
        // SAFETY: as above.
        unsafe { OBJ_sigid_free() };
        // SAFETY: NULL out-pointers are allowed.
        let found = unsafe { OBJ_find_sigid_algs(6001, ptr::null_mut(), ptr::null_mut()) };
        // SAFETY: as above.
        let by_algs = unsafe { OBJ_find_sigid_by_algs(ptr::null_mut(), 672, 1087) };
        assert_eq!((found, by_algs), (0, 0));
        // SAFETY: no preconditions; the table starts again.
        assert_eq!(unsafe { OBJ_add_sigid(6001, 672, 1087) }, 1);
        // SAFETY: as above.
        unsafe { OBJ_sigid_free() };
    }
}
