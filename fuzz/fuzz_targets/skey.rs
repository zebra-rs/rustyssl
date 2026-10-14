//! Fuzzes opaque symmetric keys (`EVP_SKEY`) through the C ABI: arbitrary octets imported as
//! each key type must give back the same raw key (or be refused for a length the type doesn't
//! take), survive moving to their own provider, and key a cipher through `EVP_CipherInit_SKEY`
//! exactly as the raw octets do through `EVP_CipherInit_ex2`, with or without an IV.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn EVP_SKEY_import_raw_key(libctx: *mut c_void, name: *const c_char, key: *mut u8, len: usize, props: *const c_char) -> *mut c_void;
    fn EVP_SKEY_get0_raw_key(skey: *const c_void, key: *mut *const u8, len: *mut usize) -> c_int;
    fn EVP_SKEY_to_provider(skey: *mut c_void, libctx: *mut c_void, prov: *mut c_void, props: *const c_char) -> *mut c_void;
    fn EVP_SKEY_free(skey: *mut c_void);
    fn EVP_CIPHER_fetch(libctx: *mut c_void, name: *const c_char, props: *const c_char) -> *mut c_void;
    fn EVP_CIPHER_free(c: *mut c_void);
    fn EVP_CIPHER_get_key_length(c: *const c_void) -> c_int;
    fn EVP_CIPHER_get_iv_length(c: *const c_void) -> c_int;
    fn EVP_CIPHER_CTX_new() -> *mut c_void;
    fn EVP_CIPHER_CTX_free(ctx: *mut c_void);
    fn EVP_CipherInit_SKEY(ctx: *mut c_void, c: *const c_void, skey: *mut c_void, iv: *const u8, ivlen: usize, enc: c_int, params: *const c_void) -> c_int;
    fn EVP_CipherInit_ex2(ctx: *mut c_void, c: *const c_void, key: *const u8, iv: *const u8, enc: c_int, params: *const c_void) -> c_int;
    fn EVP_CipherUpdate(ctx: *mut c_void, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    fn EVP_CipherFinal_ex(ctx: *mut c_void, out: *mut u8, outl: *mut c_int) -> c_int;
    fn ERR_clear_error();
}

const TYPES: [&core::ffi::CStr; 3] = [c"AES", c"GENERIC-SECRET", c"NO-SUCH-TYPE"];
const CIPHERS: [&core::ffi::CStr; 6] = [
    c"AES-128-CBC",
    c"AES-256-CTR",
    c"AES-192-ECB",
    c"AES-128-GCM",
    c"CHACHA20",
    c"ARIA-256-CFB",
];

/// Runs `data` through a cipher set up by `init`; `None` if any step fails.
fn run(cipher: *const c_void, init: impl FnOnce(*mut c_void) -> c_int, enc: c_int, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; data.len() + 64];
    let (mut n, mut f) = (0, 0);
    // SAFETY: a new context, freed below; buffers of the right sizes.
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let ok = init(ctx) == 1
            && EVP_CipherUpdate(ctx, out.as_mut_ptr(), &raw mut n, data.as_ptr(), c_int::try_from(data.len()).unwrap()) == 1
            && EVP_CipherFinal_ex(ctx, out.as_mut_ptr().add(usize::try_from(n).unwrap()), &raw mut f) == 1;
        EVP_CIPHER_CTX_free(ctx);
        let _ = cipher;
        ok.then(|| {
            out.truncate(usize::try_from(n + f).unwrap());
            out
        })
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 3 {
        return;
    }
    let (head, rest) = input.split_at(3);
    let (key, data) = rest.split_at(rest.len().min(usize::from(head[1] % 65)));
    let kind = TYPES[usize::from(head[0] % 3)];
    let mut copy = key.to_vec();
    // SAFETY: the default context, static names, and the copy's octets; everything made here
    // is freed here.
    unsafe {
        let k = EVP_SKEY_import_raw_key(ptr::null_mut(), kind.as_ptr(), copy.as_mut_ptr(), copy.len(), ptr::null());
        let takes = match head[0] % 3 {
            0 => matches!(key.len(), 16 | 24 | 32),
            _ => !key.is_empty(),
        };
        assert_eq!(!k.is_null(), takes);
        if k.is_null() {
            ERR_clear_error();
            return;
        }
        let (mut raw, mut len) = (ptr::null(), 0usize);
        assert_eq!(EVP_SKEY_get0_raw_key(k, &raw mut raw, &raw mut len), 1);
        assert_eq!(core::slice::from_raw_parts(raw, len), key);
        let same = EVP_SKEY_to_provider(k, ptr::null_mut(), ptr::null_mut(), ptr::null());
        assert_eq!(same, k);
        EVP_SKEY_free(same);

        let cipher = EVP_CIPHER_fetch(ptr::null_mut(), CIPHERS[usize::from(head[2] % 6)].as_ptr(), ptr::null());
        assert!(!cipher.is_null());
        let enc = c_int::from(head[2] & 0x80 == 0);
        let ivlen = usize::try_from(EVP_CIPHER_get_iv_length(cipher)).unwrap();
        let iv = [0x5au8; 32];
        let data = &data[..data.len().min(4096)];
        let with_skey = run(cipher, |ctx| EVP_CipherInit_SKEY(ctx, cipher, k, iv.as_ptr(), ivlen, enc, ptr::null()), enc, data);
        if usize::try_from(EVP_CIPHER_get_key_length(cipher)).unwrap() == key.len() {
            let with_raw = run(cipher, |ctx| EVP_CipherInit_ex2(ctx, cipher, key.as_ptr(), iv.as_ptr(), enc, ptr::null()), enc, data);
            assert_eq!(with_skey, with_raw);
        } else {
            assert!(with_skey.is_none() || head[2] % 6 == 4);
        }
        EVP_CIPHER_free(cipher);
        EVP_SKEY_free(k);
        ERR_clear_error();
    }
});
