//! Fuzzes the EVP filters (`BIO_f_cipher`, `BIO_f_md`) through the C ABI: arbitrary octets
//! written through an encrypting filter in pieces of arbitrary sizes and flushed must equal
//! `EVP_Encrypt*` at once, and read back through a decrypting filter in arbitrary chunks (some
//! ciphertexts corrupted, some cut short) must give the plaintext or fail without going out of
//! bounds (ASan); a digest filter written and read in pieces must give `EVP_Digest`'s digest.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const c_void;
    fn BIO_f_cipher() -> *const c_void;
    fn BIO_f_md() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut c_void;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut c_void;
    fn BIO_push(b: *mut c_void, next: *mut c_void) -> *mut c_void;
    fn BIO_free_all(b: *mut c_void);
    fn BIO_write(b: *mut c_void, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut c_void, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_gets(b: *mut c_void, buf: *mut c_char, size: c_int) -> c_int;
    fn BIO_ctrl(b: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_set_cipher(b: *mut c_void, c: *const c_void, k: *const u8, i: *const u8, e: c_int) -> c_int;
    fn EVP_get_cipherbyname(name: *const c_char) -> *const c_void;
    fn EVP_get_digestbyname(name: *const c_char) -> *const c_void;
    fn EVP_CIPHER_CTX_new() -> *mut c_void;
    fn EVP_CIPHER_CTX_free(ctx: *mut c_void);
    fn EVP_CipherInit_ex(ctx: *mut c_void, c: *const c_void, e: *mut c_void, k: *const u8, i: *const u8, enc: c_int) -> c_int;
    fn EVP_CipherUpdate(ctx: *mut c_void, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    fn EVP_CipherFinal_ex(ctx: *mut c_void, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_Digest(data: *const c_void, n: usize, md: *mut u8, len: *mut c_uint, t: *const c_void, e: *mut c_void) -> c_int;
    fn ERR_clear_error();
}

const BIO_CTRL_FLUSH: c_int = 11;
const BIO_CTRL_INFO: c_int = 3;
const BIO_C_SET_MD: c_int = 111;

const CIPHERS: [&core::ffi::CStr; 8] = [
    c"aes-128-cbc",
    c"aes-256-ecb",
    c"aes-128-ctr",
    c"aes-192-cfb8",
    c"des-ede3-cbc",
    c"chacha20",
    c"camellia-256-cbc",
    c"aes-128-ofb",
];
const DIGESTS: [&core::ffi::CStr; 4] = [c"sha256", c"sha1", c"md5", c"sha512"];
const KEY: [u8; 64] = [0x5a; 64];
const IV: [u8; 32] = [0xa5; 32];

/// `EVP_Cipher*` of `data` at once (`None` if it fails, as decryption of a bad ciphertext does).
fn at_once(cipher: *const c_void, data: &[u8], enc: c_int) -> Option<Vec<u8>> {
    let mut out = vec![0u8; data.len() + 64];
    let (mut n, mut f) = (0, 0);
    // SAFETY: a new context, freed below; buffers of the right sizes.
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let ok = EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), KEY.as_ptr(), IV.as_ptr(), enc) == 1
            && EVP_CipherUpdate(ctx, out.as_mut_ptr(), &raw mut n, data.as_ptr(), c_int::try_from(data.len()).unwrap()) == 1
            && EVP_CipherFinal_ex(ctx, out.as_mut_ptr().add(usize::try_from(n).unwrap()), &raw mut f) == 1;
        EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return None;
        }
    }
    out.truncate(usize::try_from(n + f).unwrap());
    Some(out)
}

/// Reads all through `b` in chunks of the sizes `sizes` cycles through.
fn read_all(b: *mut c_void, sizes: &[usize]) -> Vec<u8> {
    let mut out = Vec::new();
    for size in sizes.iter().cycle() {
        let mut buf = vec![0u8; *size].into_boxed_slice();
        // SAFETY: `buf` has room for `size` octets.
        let r = unsafe { BIO_read(b, buf.as_mut_ptr().cast(), c_int::try_from(*size).unwrap()) };
        if r <= 0 || out.len() > 1 << 16 {
            break;
        }
        let r = usize::try_from(r).unwrap();
        assert!(r <= *size);
        out.extend_from_slice(&buf[..r]);
    }
    out
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 4 {
        return;
    }
    let (head, data) = input.split_at(4);
    let sizes: Vec<usize> = head[1..].iter().map(|b| [1, 15, 16, 17, 255, 256, 257, 300, 4096, 5000][usize::from(*b % 10)] + usize::from(*b / 10 % 4)).collect();
    // SAFETY: the built-in methods and the library's ciphers and digests; every chain made
    // here is freed here.
    unsafe {
        if head[0] & 0x80 != 0 {
            let md = EVP_get_digestbyname(DIGESTS[usize::from(head[0] % 4)].as_ptr());
            let mut want = [0u8; 64];
            let mut len: c_uint = 0;
            assert_eq!(EVP_Digest(data.as_ptr().cast(), data.len(), want.as_mut_ptr(), &raw mut len, md, ptr::null_mut()), 1);
            let want = &want[..usize::try_from(len).unwrap()];
            // Written in pieces.
            let b = BIO_push(BIO_new(BIO_f_md()), BIO_new(BIO_s_mem()));
            assert_eq!(BIO_ctrl(b, BIO_C_SET_MD, 0, md.cast_mut()), 1);
            for (i, piece) in data.chunks(sizes[0]).enumerate() {
                let _ = i;
                assert_eq!(BIO_write(b, piece.as_ptr().cast(), c_int::try_from(piece.len()).unwrap()), c_int::try_from(piece.len()).unwrap_or(0).max(0));
            }
            let mut got = [0u8; 64];
            let r = BIO_gets(b, got.as_mut_ptr().cast(), 64);
            assert_eq!(&got[..usize::try_from(r).unwrap()], want);
            BIO_free_all(b);
            // Read in chunks.
            let copy = data.to_vec().into_boxed_slice();
            let b = BIO_push(BIO_new(BIO_f_md()), BIO_new_mem_buf(copy.as_ptr().cast(), c_int::try_from(copy.len()).unwrap()));
            assert_eq!(BIO_ctrl(b, BIO_C_SET_MD, 0, md.cast_mut()), 1);
            assert_eq!(read_all(b, &sizes), data);
            let r = BIO_gets(b, got.as_mut_ptr().cast(), 64);
            assert_eq!(&got[..usize::try_from(r).unwrap()], want);
            BIO_free_all(b);
            ERR_clear_error();
            return;
        }
        let cipher = EVP_get_cipherbyname(CIPHERS[usize::from(head[0] % 8)].as_ptr());
        assert!(!cipher.is_null());
        // Encrypted in pieces and flushed: the same as at once.
        let mem = BIO_new(BIO_s_mem());
        let b = BIO_push(BIO_new(BIO_f_cipher()), mem);
        assert_eq!(BIO_set_cipher(b, cipher, KEY.as_ptr(), IV.as_ptr(), 1), 1);
        for piece in data.chunks(sizes[1]) {
            assert_eq!(BIO_write(b, piece.as_ptr().cast(), c_int::try_from(piece.len()).unwrap()), c_int::try_from(piece.len()).unwrap());
        }
        assert_eq!(BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut()), 1);
        let mut p: *mut u8 = ptr::null_mut();
        let n = BIO_ctrl(mem, BIO_CTRL_INFO, 0, (&raw mut p).cast());
        let written = if n > 0 { core::slice::from_raw_parts(p, usize::try_from(n).unwrap()).to_vec() } else { Vec::new() };
        let want = at_once(cipher, data, 1).unwrap();
        assert_eq!(written, want);
        BIO_free_all(b);
        // Decrypted in chunks: the plaintext; or, corrupted or cut short, whatever decryption
        // at once gives, if anything.
        let mut ct = want;
        if head[0] & 0x40 != 0 && !ct.is_empty() {
            let at = usize::from(head[1]) % ct.len();
            ct[at] ^= 0x10;
        }
        if head[0] & 0x20 != 0 {
            ct.truncate(ct.len().saturating_sub(usize::from(head[2] % 17)));
        }
        let copy = ct.clone().into_boxed_slice();
        let b = BIO_push(BIO_new(BIO_f_cipher()), BIO_new_mem_buf(copy.as_ptr().cast(), c_int::try_from(copy.len()).unwrap()));
        assert_eq!(BIO_set_cipher(b, cipher, KEY.as_ptr(), IV.as_ptr(), 0), 1);
        let got = read_all(b, &sizes);
        let status = BIO_ctrl(b, 113, 0, ptr::null_mut());
        match at_once(cipher, &ct, 0) {
            Some(plain) => {
                assert_eq!(got, plain);
                assert_eq!(status, 1);
            }
            None => assert_eq!(status, 0),
        }
        if head[0] & 0x60 == 0 {
            assert_eq!(got, data);
        }
        BIO_free_all(b);
        ERR_clear_error();
    }
});
