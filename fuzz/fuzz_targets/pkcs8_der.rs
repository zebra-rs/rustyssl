//! Fuzzes the decoders of PKCS#8's PrivateKeyInfo (`d2i_PKCS8_PRIV_KEY_INFO`), `X509_SIG`
//! (PKCS#8's EncryptedPrivateKeyInfo, PKCS#1's DigestInfo), attributes, and SEQUENCE OF
//! AlgorithmIdentifier, which key files and signatures carry from untrusted sources. Nothing may
//! crash or read out of bounds (ASan), a decoder may consume only the input, and a value it
//! makes must encode again; if that encoding decodes, it must encode the same way. (As in
//! OpenSSL, it needn't decode: an ANY holding a constructed end-of-contents encodes as an
//! empty one, which reads as the end of an indefinite length.)

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_ITEM, ASN1_OBJECT, ASN1_VALUE, PKCS8_PRIV_KEY_INFO, X509_ALGOR};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_item_d2i(
        a: *mut *mut ASN1_VALUE,
        input: *mut *const c_uchar,
        len: c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(a: *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int;
    fn ASN1_item_free(a: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn PKCS8_PRIV_KEY_INFO_it() -> *const ASN1_ITEM;
    fn X509_SIG_it() -> *const ASN1_ITEM;
    fn X509_ATTRIBUTE_it() -> *const ASN1_ITEM;
    fn X509_ALGORS_it() -> *const ASN1_ITEM;
    fn PKCS8_pkey_get0(
        ppkalg: *mut *const ASN1_OBJECT,
        pk: *mut *const c_uchar,
        ppklen: *mut c_int,
        pa: *mut *const X509_ALGOR,
        p8: *const PKCS8_PRIV_KEY_INFO,
    ) -> c_int;
    fn PKCS8_pkey_get0_attrs(p8: *const PKCS8_PRIV_KEY_INFO) -> *const c_void;
    fn X509at_get_attr_count(x: *const c_void) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// The value's DER (owned by the caller), or `None`.
fn encode(v: *const ASN1_VALUE, it: *const ASN1_ITEM) -> Option<Vec<u8>> {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live value of the item.
    let n = unsafe { ASN1_item_i2d(v, &mut der, it) };
    if n <= 0 {
        return None;
    }
    // SAFETY: the encoding of `n` octets, freed once.
    let out = unsafe { core::slice::from_raw_parts(der, n as usize) }.to_vec();
    // SAFETY: as above.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
    Some(out)
}

fn decode(input: &[u8], it: *const ASN1_ITEM) -> (*mut ASN1_VALUE, usize) {
    let mut p = input.as_ptr();
    let len = c_long::try_from(input.len()).unwrap();
    // SAFETY: `input` holds `len` octets; the item.
    let v = unsafe { ASN1_item_d2i(ptr::null_mut(), &mut p, len, it) };
    (v, p as usize - input.as_ptr() as usize)
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, input)) = input.split_first() else {
        return;
    };
    // SAFETY: no preconditions.
    let it = unsafe {
        match flags % 4 {
            0 => PKCS8_PRIV_KEY_INFO_it(),
            1 => X509_SIG_it(),
            2 => X509_ATTRIBUTE_it(),
            _ => X509_ALGORS_it(),
        }
    };
    let (v, used) = decode(input, it);
    if v.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        if flags % 4 == 0 {
            let p8 = v.cast::<PKCS8_PRIV_KEY_INFO>();
            let (mut o, mut pk, mut len, mut pa) = (ptr::null(), ptr::null(), 0, ptr::null());
            // SAFETY: a live PrivateKeyInfo; locals.
            unsafe {
                PKCS8_pkey_get0(&mut o, &mut pk, &mut len, &mut pa, p8);
                X509at_get_attr_count(PKCS8_pkey_get0_attrs(p8));
            }
        }
        let der = encode(v, it).expect("a decoded value encodes");
        let (back, n) = decode(&der, it);
        if !back.is_null() {
            assert_eq!(n, der.len(), "its encoding decodes whole");
            assert_eq!(encode(back, it).as_deref(), Some(&der[..]), "and encodes the same");
        }
        // SAFETY: values made here (or NULL), freed once.
        unsafe {
            ASN1_item_free(back, it);
            ASN1_item_free(v, it);
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
