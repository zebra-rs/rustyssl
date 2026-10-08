//! The per-thread error queue that OpenSSL's `ERR_*` functions read. Exports raise errors here
//! through [`raise`]; step 1.4 of the plan adds the `ERR_*` exports themselves.
//!
//! OpenSSL keeps a ring of `ERR_NUM_ERRORS` slots per thread, which holds one fewer error than
//! it has slots, and raising an error into a full ring drops the oldest. [`capacity`] follows
//! that; step 1.4 confirms it against the reference build.

use core::ffi::{c_int, c_ulong};
use std::cell::RefCell;
use std::collections::VecDeque;

use rustssl_abi::{ERR_LIB_MASK, ERR_LIB_OFFSET, ERR_NUM_ERRORS, ERR_REASON_MASK};

/// How many errors a thread's queue holds.
fn capacity() -> usize {
    usize::try_from(ERR_NUM_ERRORS).map_or(1, |slots| slots.saturating_sub(1).max(1))
}

/// One error on the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Error {
    /// The packed code `ERR_get_error` returns: `ERR_PACK(library, 0, reason)`.
    pub(crate) code: c_ulong,
    /// The function that raised it, which `ERR_get_error_all` reports.
    pub(crate) function: &'static str,
}

thread_local! {
    static QUEUE: RefCell<VecDeque<Error>> = const { RefCell::new(VecDeque::new()) };
}

/// `ERR_PACK(library, 0, reason)` from `err.h`.
pub(crate) fn pack(library: c_int, reason: c_int) -> c_ulong {
    let library = c_ulong::from((library & ERR_LIB_MASK).cast_unsigned());
    let reason = c_ulong::from((reason & ERR_REASON_MASK).cast_unsigned());
    let offset = u32::try_from(ERR_LIB_OFFSET).unwrap_or_default();
    library.checked_shl(offset).unwrap_or_default() | reason
}

/// Raises an error, as `ERR_raise(library, reason)` does in OpenSSL, on behalf of the exported
/// C function `function`.
pub(crate) fn raise(library: c_int, reason: c_int, function: &'static str) {
    let error = Error {
        code: pack(library, reason),
        function,
    };
    // During thread teardown the queue may already be gone, and the queue is never borrowed
    // across a call that could raise; either way the error is dropped rather than panicking,
    // as OpenSSL drops one it can't record.
    let _ = QUEUE.try_with(|queue| {
        if let Ok(mut queue) = queue.try_borrow_mut() {
            if queue.len() >= capacity() {
                queue.pop_front();
            }
            queue.push_back(error);
        }
    });
}

/// Drops this thread's errors, as OpenSSL does when `OPENSSL_thread_stop` frees the thread's
/// error state.
pub(crate) fn clear_thread() {
    let _ = QUEUE.try_with(|queue| {
        if let Ok(mut queue) = queue.try_borrow_mut() {
            queue.clear();
        }
    });
}

/// Removes and returns this thread's errors, oldest first.
#[cfg(test)]
pub(crate) fn take_all() -> Vec<Error> {
    QUEUE.with(|queue| queue.borrow_mut().drain(..).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustssl_abi::{ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT};

    #[test]
    fn packs_like_err_pack() {
        // ERR_PACK(ERR_LIB_BUF, 0, ERR_R_PASSED_INVALID_ARGUMENT): the library in bits 23-30,
        // the reason (with its flags) in bits 0-22.
        let code = pack(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT);
        assert_eq!(code >> 23, c_ulong::from(ERR_LIB_BUF.cast_unsigned()));
        let reason =
            c_ulong::from((ERR_R_PASSED_INVALID_ARGUMENT & ERR_REASON_MASK).cast_unsigned());
        assert_eq!(code & 0x7f_ffff, reason);
    }

    #[test]
    fn the_queue_keeps_the_newest_errors() {
        take_all();
        let total = capacity() + 3;
        for reason in 0..total {
            raise(ERR_LIB_BUF, c_int::try_from(reason).unwrap(), "test");
        }
        let errors = take_all();
        assert_eq!(errors.len(), capacity());
        // The three oldest were dropped.
        assert_eq!(errors[0].code, pack(ERR_LIB_BUF, 3));
        assert!(take_all().is_empty());
    }
}
