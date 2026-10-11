//! Fuzzes MACs through the C ABI, against themselves: the first octets pick HMAC (with a
//! digest), CMAC (with a CBC cipher), or GMAC (with a GCM cipher), a key length, and for GMAC an
//! IV length; the rest is a script of updates of lengths read from it (over its own octets),
//! copies that take over, and reinits. The MAC of the data, however split, must equal
//! `EVP_Q_mac`'s of it whole, and HMAC's and CMAC's must equal the legacy `HMAC` and
//! `CMAC_*` functions' (CMAC's also finished early and resumed). Nothing may panic or go out of
//! bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

/// `OSSL_PARAM`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Param {
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

unsafe extern "C" {
    fn EVP_MAC_fetch(ctx: *mut c_void, name: *const c_char, props: *const c_char) -> *mut c_void;
    fn EVP_MAC_free(mac: *mut c_void);
    fn EVP_MAC_CTX_new(mac: *mut c_void) -> *mut c_void;
    fn EVP_MAC_CTX_free(ctx: *mut c_void);
    fn EVP_MAC_CTX_dup(ctx: *const c_void) -> *mut c_void;
    fn EVP_MAC_init(ctx: *mut c_void, key: *const c_uchar, keylen: usize, params: *const Param) -> c_int;
    fn EVP_MAC_update(ctx: *mut c_void, data: *const c_uchar, len: usize) -> c_int;
    fn EVP_MAC_final(ctx: *mut c_void, out: *mut c_uchar, outl: *mut usize, outsize: usize) -> c_int;
    fn EVP_Q_mac(libctx: *mut c_void, name: *const c_char, propq: *const c_char, subalg: *const c_char, params: *const Param, key: *const c_void, keylen: usize, data: *const c_uchar, datalen: usize, out: *mut c_uchar, outsize: usize, outlen: *mut usize) -> *mut c_uchar;
    fn OSSL_PARAM_construct_utf8_string(key: *const c_char, buf: *mut c_char, bsize: usize) -> Param;
    fn OSSL_PARAM_construct_octet_string(key: *const c_char, buf: *mut c_void, bsize: usize) -> Param;
    fn OSSL_PARAM_construct_end() -> Param;
    fn EVP_get_digestbyname(name: *const c_char) -> *const c_void;
    fn EVP_get_cipherbyname(name: *const c_char) -> *const c_void;
    fn HMAC(md: *const c_void, key: *const c_void, key_len: c_int, data: *const c_uchar, data_len: usize, out: *mut c_uchar, out_len: *mut c_uint) -> *mut c_uchar;
    fn CMAC_CTX_new() -> *mut c_void;
    fn CMAC_CTX_free(ctx: *mut c_void);
    fn CMAC_Init(ctx: *mut c_void, key: *const c_void, keylen: usize, cipher: *const c_void, engine: *mut c_void) -> c_int;
    fn CMAC_Update(ctx: *mut c_void, data: *const c_void, len: usize) -> c_int;
    fn CMAC_Final(ctx: *mut c_void, out: *mut c_uchar, outl: *mut usize) -> c_int;
    fn CMAC_resume(ctx: *mut c_void) -> c_int;
    fn ERR_clear_error();
}

const DIGESTS: [&CStr; 8] = [c"SHA1", c"SHA256", c"SHA512", c"SHA3-256", c"MD5", c"SM3", c"BLAKE2b512", c"MD5-SHA1"];
const CBCS: [&CStr; 5] = [c"AES-128-CBC", c"AES-256-CBC", c"DES-EDE3-CBC", c"ARIA-192-CBC", c"SM4-CBC"];
const GCMS: [&CStr; 3] = [c"AES-128-GCM", c"AES-256-GCM", c"ARIA-128-GCM"];

fn mac(head: &[u8], script: &[u8]) {
    let [which, alg, keylen, ivlen] = *head else { return };
    let (name, sub, param): (&CStr, &CStr, &CStr) = match which % 3 {
        0 => (c"HMAC", DIGESTS[usize::from(alg) % DIGESTS.len()], c"digest"),
        1 => (c"CMAC", CBCS[usize::from(alg) % CBCS.len()], c"cipher"),
        _ => (c"GMAC", GCMS[usize::from(alg) % GCMS.len()], c"cipher"),
    };
    // HMAC takes any key; the ciphers want theirs (mostly given, sometimes not).
    let n = match (which % 3, keylen) {
        (0, _) | (_, 200..) => usize::from(keylen) % 70,
        _ => [16, 24, 32][usize::from(keylen) % 3],
    };
    let key: Vec<u8> = (0..n).map(|i| i as u8 ^ 0x3c).collect();
    let iv: Vec<u8> = (0..1 + usize::from(ivlen) % 20).map(|i| i as u8 ^ 0xc3).collect();
    // SAFETY: static strings and the buffers above, which outlive the parameters.
    let params = unsafe {
        let mut p = vec![OSSL_PARAM_construct_utf8_string(c"x".as_ptr(), ptr::null_mut(), 0); 3];
        p[0] = OSSL_PARAM_construct_utf8_string(param.as_ptr(), sub.as_ptr().cast_mut(), 0);
        p[1] = if which % 3 == 2 {
            OSSL_PARAM_construct_octet_string(c"iv".as_ptr(), iv.as_ptr().cast_mut().cast(), iv.len())
        } else {
            OSSL_PARAM_construct_end()
        };
        p[2] = OSSL_PARAM_construct_end();
        p
    };

    // The whole data, at once.
    let mut data = Vec::new();
    let mut want = [0u8; 64];
    let mut want_len = 0usize;
    // SAFETY: the buffers above; room for any MAC.
    let fetched = unsafe { EVP_MAC_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    assert!(!fetched.is_null());
    // SAFETY: as above.
    let mut ctx = unsafe { EVP_MAC_CTX_new(fetched) };
    // SAFETY: as above.
    unsafe { EVP_MAC_free(fetched) };
    // SAFETY: as above.
    let keyed = unsafe { EVP_MAC_init(ctx, key.as_ptr(), key.len(), params.as_ptr()) } == 1;

    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0)) * if op & 0x80 != 0 { 9 } else { 1 };
        let piece = &tail[..len.min(tail.len())];
        match op % 4 {
            0 | 1 => {
                // SAFETY: the piece's octets.
                let r = unsafe { EVP_MAC_update(ctx, piece.as_ptr(), piece.len()) };
                assert!(r == 1 || !keyed);
                if r == 1 {
                    data.extend_from_slice(piece);
                }
            }
            2 => {
                // SAFETY: a live context.
                let dup = unsafe { EVP_MAC_CTX_dup(ctx) };
                if !dup.is_null() {
                    // SAFETY: the old context, replaced by its copy.
                    unsafe { EVP_MAC_CTX_free(ctx) };
                    ctx = dup;
                }
            }
            _ if keyed && which % 3 != 2 => {
                // Start over (GMAC can't, without a new IV).
                // SAFETY: a live context.
                assert_eq!(unsafe { EVP_MAC_init(ctx, ptr::null(), 0, ptr::null()) }, 1);
                data.clear();
            }
            _ => {}
        }
        rest = tail.get(1 + piece.len()..).unwrap_or_default();
    }
    if keyed {
        // SAFETY: room for any MAC.
        let r = unsafe { EVP_MAC_final(ctx, want.as_mut_ptr(), &raw mut want_len, want.len()) };
        assert_eq!(r, 1);
    }
    // SAFETY: the context made here.
    unsafe { EVP_MAC_CTX_free(ctx) };
    if !keyed {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        return;
    }

    // The same, at once.
    let mut once = [0u8; 64];
    let mut once_len = 0usize;
    // SAFETY: the buffers above, which hold their lengths.
    let p = unsafe {
        EVP_Q_mac(ptr::null_mut(), name.as_ptr(), ptr::null(), sub.as_ptr(), params[1..].as_ptr(), key.as_ptr().cast(), key.len(), data.as_ptr(), data.len(), once.as_mut_ptr(), once.len(), &raw mut once_len)
    };
    // An empty key is the data for EVP_Q_mac; skip that case.
    if !key.is_empty() {
        assert_eq!(p, once.as_mut_ptr());
        assert_eq!(&once[..once_len], &want[..want_len]);
    }

    match which % 3 {
        0 => {
            let mut legacy = [0u8; 64];
            let mut n: c_uint = 0;
            // SAFETY: a static name; the buffers above.
            let md = unsafe { EVP_get_digestbyname(sub.as_ptr()) };
            if !md.is_null() {
                // SAFETY: as above.
                let r = unsafe { HMAC(md, key.as_ptr().cast(), key.len() as c_int, data.as_ptr(), data.len(), legacy.as_mut_ptr(), &raw mut n) };
                assert!(!r.is_null());
                assert_eq!(&legacy[..n as usize], &want[..want_len]);
            }
        }
        1 => {
            let mut legacy = [0u8; 64];
            let mut n = 0usize;
            // SAFETY: a static name; the buffers above; a context made and freed here.
            unsafe {
                let cipher = EVP_get_cipherbyname(sub.as_ptr());
                let c = CMAC_CTX_new();
                assert_eq!(CMAC_Init(c, key.as_ptr().cast(), key.len(), cipher, ptr::null_mut()), 1);
                let half = data.len() / 2;
                assert_eq!(CMAC_Update(c, data.as_ptr().cast(), half), 1);
                let mut early = [0u8; 32];
                assert_eq!(CMAC_Final(c, early.as_mut_ptr(), &raw mut n), 1);
                assert_eq!(CMAC_resume(c), 1);
                assert_eq!(CMAC_Update(c, data[half..].as_ptr().cast(), data.len() - half), 1);
                assert_eq!(CMAC_Final(c, legacy.as_mut_ptr(), &raw mut n), 1);
                CMAC_CTX_free(c);
            }
            assert_eq!(&legacy[..n], &want[..want_len]);
        }
        _ => {}
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
}

fuzz_target!(|input: &[u8]| {
    if input.len() >= 4 {
        mac(&input[..4], &input[4..]);
    }
});
