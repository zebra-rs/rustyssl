//! The state behind OpenSSL's deprecated low-level APIs (`SHA256_Init(3)`, `MD5(3)`,
//! `AES_encrypt(3)`, `DES_ecb_encrypt(3)`, ...), which OpenSSL 3 still exports.
//!
//! Applications keep these contexts themselves, often on the stack, and some read, write, or
//! copy their fields, so the whole state is the C struct's. These types mirror each struct field
//! by field: the FFI layer copies a struct in, calls a method, and copies it back.

pub mod aead;
pub mod aes;
pub mod des;
pub mod hash;
pub mod modes;

/// Copies `src` into `buf` from octet `at` on, as far as `buf` reaches.
fn put(buf: &mut [u8], at: usize, src: &[u8]) {
    for (d, s) in buf.iter_mut().skip(at).zip(src) {
        *d = *s;
    }
}

/// Zeroes `buf` from octet `from` on.
fn clear_from(buf: &mut [u8], from: usize) {
    for d in buf.iter_mut().skip(from) {
        *d = 0;
    }
}
