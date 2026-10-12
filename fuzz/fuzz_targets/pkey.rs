//! Fuzzes keys made from parameters through the C ABI (`EVP_PKEY_fromdata`): the input picks a
//! MAC or KDF key type and a selection, then builds a parameter array of private keys, ciphers,
//! and properties (of the right types or not, with any lengths). A key made with a private key
//! must give it back raw and in its export, copy and compare equal to its copy, take a new key
//! through its parameters, and serve as a generation template. Nothing may panic or go out of
//! bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Pkey = c_void;
type Ctx = c_void;

/// `OSSL_PARAM`.
#[repr(C)]
struct Param {
    key: *const c_char,
    data_type: u32,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

const UTF8_STRING: u32 = 4;
const OCTET_STRING: u32 = 5;
const SELECT_ALL: c_int = 0x87;

unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        lib: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut Ctx;
    fn EVP_PKEY_CTX_new(pkey: *mut Pkey, e: *mut c_void) -> *mut Ctx;
    fn EVP_PKEY_CTX_free(c: *mut Ctx);
    fn EVP_PKEY_fromdata_init(c: *mut Ctx) -> c_int;
    fn EVP_PKEY_fromdata(
        c: *mut Ctx,
        pk: *mut *mut Pkey,
        selection: c_int,
        params: *mut Param,
    ) -> c_int;
    fn EVP_PKEY_keygen_init(c: *mut Ctx) -> c_int;
    fn EVP_PKEY_CTX_set_mac_key(c: *mut Ctx, key: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_keygen(c: *mut Ctx, pk: *mut *mut Pkey) -> c_int;
    fn EVP_PKEY_free(k: *mut Pkey);
    fn EVP_PKEY_dup(k: *mut Pkey) -> *mut Pkey;
    fn EVP_PKEY_eq(a: *const Pkey, b: *const Pkey) -> c_int;
    fn EVP_PKEY_get_raw_private_key(k: *const Pkey, out: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_set_octet_string_param(
        k: *mut Pkey,
        name: *const c_char,
        buf: *const u8,
        len: usize,
    ) -> c_int;
    fn EVP_PKEY_todata(k: *const Pkey, selection: c_int, params: *mut *mut Param) -> c_int;
    fn OSSL_PARAM_free(p: *mut Param);
    fn ERR_clear_error();
}

const TYPES: [&core::ffi::CStr; 7] = [
    c"HMAC",
    c"SIPHASH",
    c"POLY1305",
    c"CMAC",
    c"HKDF",
    c"TLS1-PRF",
    c"SCRYPT",
];
const CIPHERS: [&core::ffi::CStr; 5] = [
    c"AES-128-CBC",
    c"AES-256-CBC",
    c"DES-EDE3-CBC",
    c"NOPE",
    c"AES-128-GCM",
];
const PROPS: [&core::ffi::CStr; 3] = [c"provider=default", c"provider=base", c"?x=y"];

/// The raw private key of `k`, if it has one.
fn raw(k: *const Pkey) -> Option<Vec<u8>> {
    let mut len = 0usize;
    // SAFETY: a live key; only the size.
    if unsafe { EVP_PKEY_get_raw_private_key(k, ptr::null_mut(), &raw mut len) } != 1 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: as above; a buffer of that size.
    (unsafe { EVP_PKEY_get_raw_private_key(k, buf.as_mut_ptr(), &raw mut len) } == 1).then(|| {
        buf.truncate(len);
        buf
    })
}

fuzz_target!(|data: &[u8]| {
    let [t, sel, n, rest @ ..] = data else { return };
    let name = TYPES[usize::from(*t) % TYPES.len()];
    let selection = c_int::from(*sel & 0x87);
    // Up to four parameters, each a kind byte and a length byte then its octets.
    let mut octets: Vec<Vec<u8>> = Vec::new();
    let mut params: Vec<Param> = Vec::new();
    let mut at = rest;
    // The first `priv` parameter is the one imported (`OSSL_PARAM_locate`): its octets, or
    // `None` for one of the wrong type.
    let mut key: Option<Option<Vec<u8>>> = None;
    for _ in 0..usize::from(*n % 5) {
        let [kind, len, tail @ ..] = at else { break };
        let len = usize::from(*len).min(tail.len());
        let (bytes, tail) = tail.split_at(len);
        at = tail;
        octets.push(bytes.to_vec());
        let p = octets
            .last_mut()
            .map_or(ptr::null_mut(), |o| o.as_mut_ptr().cast());
        let param = match kind % 6 {
            0 | 1 => {
                if key.is_none() {
                    key = Some(Some(bytes.to_vec()));
                }
                Param {
                    key: c"priv".as_ptr(),
                    data_type: OCTET_STRING,
                    data: p,
                    data_size: len,
                    return_size: usize::MAX,
                }
            }
            2 => Param {
                key: c"cipher".as_ptr(),
                data_type: UTF8_STRING,
                data: CIPHERS[len % CIPHERS.len()].as_ptr().cast_mut().cast(),
                data_size: 0,
                return_size: usize::MAX,
            },
            3 => Param {
                key: c"properties".as_ptr(),
                data_type: UTF8_STRING,
                data: PROPS[len % PROPS.len()].as_ptr().cast_mut().cast(),
                data_size: 0,
                return_size: usize::MAX,
            },
            4 => {
                if key.is_none() {
                    key = Some(None);
                }
                Param {
                    key: c"priv".as_ptr(),
                    data_type: UTF8_STRING,
                    data: c"abc".as_ptr().cast_mut().cast(),
                    data_size: 0,
                    return_size: usize::MAX,
                }
            }
            _ => Param {
                key: c"engine".as_ptr(),
                data_type: UTF8_STRING,
                data: c"e".as_ptr().cast_mut().cast(),
                data_size: 0,
                return_size: usize::MAX,
            },
        };
        params.push(param);
    }
    params.push(Param {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    });

    // SAFETY: the default context; a static name.
    let c = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    assert!(!c.is_null());
    let mut k: *mut Pkey = ptr::null_mut();
    // SAFETY: the context; the array above, which outlives the call.
    let ok = unsafe { EVP_PKEY_fromdata_init(c) } == 1
        && unsafe { EVP_PKEY_fromdata(c, &raw mut k, selection, params.as_mut_ptr()) } == 1;
    // SAFETY: made above.
    unsafe { EVP_PKEY_CTX_free(c) };
    if ok {
        assert!(!k.is_null());
        let first = raw(k);
        // A key made has the first `priv` parameter's octets.
        if let Some(want) = &key {
            assert_eq!(first.as_ref(), want.as_ref());
        }
        // SAFETY: the key, here and below.
        let d = unsafe { EVP_PKEY_dup(k) };
        if !d.is_null() {
            // SAFETY: both keys.
            assert_eq!(unsafe { EVP_PKEY_eq(k, d) }, 1);
            assert_eq!(raw(d), first);
            // SAFETY: made above.
            unsafe { EVP_PKEY_free(d) };
        }
        let mut out: *mut Param = ptr::null_mut();
        // SAFETY: the key; room for the array.
        if unsafe { EVP_PKEY_todata(k, SELECT_ALL, &raw mut out) } == 1 {
            // SAFETY: made by the export.
            unsafe { OSSL_PARAM_free(out) };
        }
        let new_key = [0x5au8; 12];
        // SAFETY: the key; a static name; the octets.
        if unsafe { EVP_PKEY_set_octet_string_param(k, c"priv".as_ptr(), new_key.as_ptr(), 12) }
            == 1
        {
            assert_eq!(raw(k).as_deref(), Some(&new_key[..]));
        }
        // As a template for generation.
        // SAFETY: the key.
        let g = unsafe { EVP_PKEY_CTX_new(k, ptr::null_mut()) };
        if !g.is_null() {
            let mut out: *mut Pkey = ptr::null_mut();
            // SAFETY: the context; the octets.
            if unsafe { EVP_PKEY_keygen_init(g) } == 1
                && unsafe { EVP_PKEY_CTX_set_mac_key(g, new_key.as_ptr(), 12) } == 1
                && unsafe { EVP_PKEY_keygen(g, &raw mut out) } == 1
            {
                assert_eq!(raw(out).as_deref(), Some(&new_key[..]));
            }
            // SAFETY: made above, or NULL.
            unsafe { EVP_PKEY_free(out) };
            // SAFETY: made above.
            unsafe { EVP_PKEY_CTX_free(g) };
        }
    } else {
        assert!(k.is_null());
    }
    // SAFETY: made above, or NULL.
    unsafe { EVP_PKEY_free(k) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
