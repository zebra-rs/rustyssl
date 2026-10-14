//! Fuzzes configuration files through `NCONF_load_bio` with either method: whatever loads,
//! every value in each section's stack must be what `NCONF_get_string` finds for its name,
//! the dump must succeed, and freeing must be clean. Includes are renamed so no file is read.
//! The same text goes through `X509V3_parse_list` (every item must have a name, and freeing
//! must be clean) and `ASN1_str2mask`.

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_long, c_void};


use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, CONF, CONF_METHOD, CONF_VALUE, OPENSSL_STACK};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn NCONF_default() -> *mut CONF_METHOD;
    fn NCONF_WIN32() -> *mut CONF_METHOD;
    fn NCONF_new(meth: *mut CONF_METHOD) -> *mut CONF;
    fn NCONF_free(conf: *mut CONF);
    fn NCONF_load_bio(conf: *mut CONF, bp: *mut BIO, eline: *mut c_long) -> c_int;
    fn NCONF_get_section_names(conf: *const CONF) -> *mut OPENSSL_STACK;
    fn NCONF_get_section(conf: *const CONF, section: *const c_char) -> *mut OPENSSL_STACK;
    fn NCONF_get_string(conf: *const CONF, group: *const c_char, name: *const c_char) -> *mut c_char;
    fn NCONF_dump_bio(conf: *const CONF, out: *mut BIO) -> c_int;
    fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> c_int;
    fn OPENSSL_sk_value(st: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
    fn X509V3_parse_list(line: *const c_char) -> *mut OPENSSL_STACK;
    fn X509V3_conf_free(conf: *mut CONF_VALUE);
    fn ASN1_str2mask(s: *const c_char, mask: *mut core::ffi::c_ulong) -> c_int;
    fn OPENSSL_sk_pop_free(st: *mut OPENSSL_STACK, f: Option<unsafe extern "C" fn(*mut c_void)>);
}

unsafe extern "C" fn free_value(v: *mut c_void) {
    unsafe { X509V3_conf_free(v.cast()) };
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, text)) = data.split_first() else { return };
    let mut text = text.to_vec();
    // `.include` (any case of the octets the parser compares) becomes `.inc1ude`.
    for i in 0..text.len() {
        if text[i..].starts_with(b".include") {
            text[i + 4] = b'1';
        }
    }
    let Ok(len) = c_int::try_from(text.len()) else { return };
    unsafe {
        let meth = if which & 1 == 0 { NCONF_default() } else { NCONF_WIN32() };
        let conf = NCONF_new(meth);
        assert!(!conf.is_null());
        let b = BIO_new_mem_buf(text.as_ptr().cast(), len);
        let mut eline: c_long = -1;
        let loaded = NCONF_load_bio(conf, b, &raw mut eline);
        assert!(loaded == 1 || eline >= 0);
        let names = NCONF_get_section_names(conf);
        for i in 0..OPENSSL_sk_num(names) {
            let section = OPENSSL_sk_value(names, i).cast::<c_char>();
            let sk = NCONF_get_section(conf, section);
            assert!(!sk.is_null());
            for j in 0..OPENSSL_sk_num(sk) {
                let v = &*OPENSSL_sk_value(sk, j).cast::<CONF_VALUE>();
                let found = NCONF_get_string(conf, section, v.name);
                assert_eq!(found, v.value, "{:?}", CStr::from_ptr(v.name));
            }
        }
        OPENSSL_sk_free(names);
        let out = BIO_new(BIO_s_mem());
        assert_eq!(NCONF_dump_bio(conf, out), 1);
        BIO_free(out);
        BIO_free(b);
        NCONF_free(conf);
        let mut line = text.clone();
        line.push(0);
        let list = X509V3_parse_list(line.as_ptr().cast());
        for i in 0..OPENSSL_sk_num(list) {
            let v = &*OPENSSL_sk_value(list, i).cast::<CONF_VALUE>();
            assert!(!v.name.is_null());
        }
        OPENSSL_sk_pop_free(list, Some(free_value));
        let mut mask: core::ffi::c_ulong = 0;
        ASN1_str2mask(line.as_ptr().cast(), &raw mut mask);
        ERR_clear_error();
    }
});
