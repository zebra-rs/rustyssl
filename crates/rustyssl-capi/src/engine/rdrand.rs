//! The `rdrand` engine (`eng_rdrand.c`): a RAND method reading Intel's RDRAND, built in on x86
//! cores that have it. Flagged `ENGINE_FLAGS_NO_REGISTER_ALL`, so only an application that asks
//! for it uses it.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{ENGINE, ENGINE_FLAGS_NO_REGISTER_ALL, RAND_METHOD};

use super::new_engine;

/// Fills `buf` from RDRAND, retrying as Intel advises; false if it keeps failing.
#[target_feature(enable = "rdrand")]
fn fill(buf: &mut [u8]) -> bool {
    for chunk in buf.chunks_mut(8) {
        let mut v: u64 = 0;
        let mut ok = false;
        for _ in 0..10 {
            // Safe here: the function enables RDRAND, which the core has (checked before this
            // engine exists).
            if core::arch::x86_64::_rdrand64_step(&mut v) == 1 {
                ok = true;
                break;
            }
        }
        if !ok {
            return false;
        }
        let bytes = v.to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(bytes.get(..n).unwrap_or(&bytes));
    }
    true
}

/// `get_random_bytes`: `num` octets into `buf`; 1, or 0.
unsafe extern "C" fn get_random_bytes(buf: *mut u8, num: c_int) -> c_int {
    crate::ffi::guard(
        rustyssl_abi::ERR_LIB_ENGINE,
        "get_random_bytes",
        || 0,
        || {
            let Ok(n) = usize::try_from(num) else {
                return 0;
            };
            if n == 0 {
                return 1;
            }
            if buf.is_null() {
                return 0;
            }
            // SAFETY: the RAND API's contract: `buf` has `num` octets.
            let out = unsafe { core::slice::from_raw_parts_mut(buf, n) };
            // SAFETY: the core has RDRAND.
            c_int::from(unsafe { fill(out) })
        },
    )
}

/// `random_status`.
unsafe extern "C" fn random_status() -> c_int {
    1
}

/// `rdrand_init`.
unsafe extern "C" fn rdrand_init(_e: *mut ENGINE) -> c_int {
    1
}

/// The method, in a static C can point to.
struct Method(RAND_METHOD);

// SAFETY: immutable, and its functions are thread-safe.
unsafe impl Sync for Method {}

static METHOD: Method = Method(RAND_METHOD {
    seed: None,
    bytes: Some(get_random_bytes),
    cleanup: None,
    add: None,
    pseudorand: Some(get_random_bytes),
    status: Some(random_status),
});

/// The `rdrand` engine, with one structural reference, or NULL when the core has no RDRAND
/// (`engine_load_rdrand_int` checks `OPENSSL_ia32cap_P`).
pub(super) fn new() -> *mut ENGINE {
    if !std::arch::is_x86_feature_detected!("rdrand") {
        return ptr::null_mut();
    }
    let e = new_engine();
    // SAFETY: just made.
    let Some(en) = (unsafe { super::engine(e) }) else {
        return ptr::null_mut();
    };
    {
        let mut f = en.lock();
        f.id = c"rdrand".as_ptr();
        f.name = c"Intel RDRAND engine".as_ptr();
        f.flags = ENGINE_FLAGS_NO_REGISTER_ALL;
        f.init = Some(rdrand_init);
        f.rand = &raw const METHOD.0;
    }
    e
}
