//! Fuzzes derivation through key contexts (`EVP_PKEY_derive` with the KDF exchanges) and the
//! ctrl translations: the input picks HKDF (and its mode) or TLS1-PRF, a digest, and the output
//! length, and splits the rest into the key (or secret), salt, and info (or seed). Deriving
//! through a key context with the typed setters, with the numbered ctrls, and with hexadecimal
//! ctrl strings must give what the KDF gives directly (`EVP_KDF_derive`) with those parameters;
//! a copy of the context (where it can be made) must derive the same. Then the rest of the input, as ctrl strings,
//! goes to a context of each KDF type. Nothing may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

/// `OSSL_PARAM`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Param {
    key: *const c_char,
    data_type: u32,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

type Ctx = c_void;

unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        lib: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut Ctx;
    fn EVP_PKEY_CTX_free(ctx: *mut Ctx);
    fn EVP_PKEY_CTX_dup(ctx: *const Ctx) -> *mut Ctx;
    fn EVP_PKEY_derive_init(ctx: *mut Ctx) -> c_int;
    fn EVP_PKEY_derive(ctx: *mut Ctx, key: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut Ctx, md: *const c_void) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_key(ctx: *mut Ctx, key: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_salt(ctx: *mut Ctx, salt: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_add1_hkdf_info(ctx: *mut Ctx, info: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_hkdf_mode(ctx: *mut Ctx, mode: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_tls1_prf_md(ctx: *mut Ctx, md: *const c_void) -> c_int;
    fn EVP_PKEY_CTX_set1_tls1_prf_secret(ctx: *mut Ctx, sec: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_add1_tls1_prf_seed(ctx: *mut Ctx, seed: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut Ctx,
        keytype: c_int,
        optype: c_int,
        cmd: c_int,
        p1: c_int,
        p2: *mut c_void,
    ) -> c_int;
    fn EVP_PKEY_CTX_ctrl_str(ctx: *mut Ctx, name: *const c_char, value: *const c_char) -> c_int;
    fn EVP_get_digestbyname(name: *const c_char) -> *const c_void;
    fn EVP_KDF_fetch(ctx: *mut c_void, name: *const c_char, props: *const c_char) -> *mut c_void;
    fn EVP_KDF_free(kdf: *mut c_void);
    fn EVP_KDF_CTX_new(kdf: *mut c_void) -> *mut c_void;
    fn EVP_KDF_CTX_free(ctx: *mut c_void);
    fn EVP_KDF_derive(ctx: *mut c_void, key: *mut u8, keylen: usize, params: *const Param)
    -> c_int;
    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> Param;
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> Param;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> Param;
    fn OSSL_PARAM_construct_end() -> Param;
    fn ERR_clear_error();
}

/// `EVP_PKEY_OP_DERIVE`.
const DERIVE: c_int = 1 << 11;
/// `EVP_PKEY_ALG_CTRL` and the KDF ctrls after it (`kdf.h`).
const ALG_CTRL: c_int = 0x1000;
const TLS_MD: c_int = ALG_CTRL;
const TLS_SECRET: c_int = ALG_CTRL + 1;
const TLS_SEED: c_int = ALG_CTRL + 2;
const HKDF_MD: c_int = ALG_CTRL + 3;
const HKDF_SALT: c_int = ALG_CTRL + 4;
const HKDF_KEY: c_int = ALG_CTRL + 5;
const HKDF_INFO: c_int = ALG_CTRL + 6;

const DIGESTS: [(&CStr, usize); 4] = [
    (c"SHA256", 32),
    (c"SHA1", 20),
    (c"SHA512", 64),
    (c"SHA3-256", 32),
];
const MODES: [&CStr; 3] = [c"EXTRACT_AND_EXPAND", c"EXTRACT_ONLY", c"EXPAND_ONLY"];

/// The inputs of one derivation.
struct Inputs<'a> {
    hkdf: bool,
    md: &'static CStr,
    mdsize: usize,
    mode: usize,
    key: &'a [u8],
    salt: &'a [u8],
    info: &'a [u8],
    outlen: usize,
}

impl Inputs<'_> {
    /// How many octets a derivation gives: the digest's size for HKDF's extraction.
    fn len(&self) -> usize {
        if self.hkdf && self.mode == 1 {
            self.mdsize
        } else {
            self.outlen
        }
    }
}

fn int(n: usize) -> c_int {
    c_int::try_from(n).unwrap_or(0)
}

fn hex(b: &[u8]) -> CString {
    let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    CString::new(s).unwrap_or_default()
}

/// The KDF's own derivation: the oracle.
fn direct(i: &Inputs<'_>) -> Option<Vec<u8>> {
    let name = if i.hkdf { c"HKDF" } else { c"TLS1-PRF" };
    // SAFETY: the default context; a static name.
    let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    // SAFETY: the method fetched above.
    let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: the reference fetched above.
    unsafe { EVP_KDF_free(kdf) };
    let mut mode = int(i.mode);
    let oct = |k: &CStr, d: &[u8]| {
        // SAFETY: a static key; the input's octets, which outlive the derivation.
        unsafe {
            OSSL_PARAM_construct_octet_string(k.as_ptr(), d.as_ptr().cast_mut().cast(), d.len())
        }
    };
    // SAFETY: a static key and name.
    let mut params = vec![unsafe {
        OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), i.md.as_ptr().cast_mut(), 0)
    }];
    if i.hkdf {
        params.push(oct(c"key", i.key));
        params.push(oct(c"salt", i.salt));
        params.push(oct(c"info", i.info));
        // SAFETY: a static key; the local, which outlives the derivation.
        params.push(unsafe { OSSL_PARAM_construct_int(c"mode".as_ptr(), &raw mut mode) });
    } else {
        params.push(oct(c"secret", i.key));
        params.push(oct(c"seed", i.info));
    }
    // SAFETY: no preconditions.
    params.push(unsafe { OSSL_PARAM_construct_end() });
    let mut out = vec![0u8; i.len()];
    // SAFETY: the context; the buffer; the array above.
    let ok = unsafe { EVP_KDF_derive(ctx, out.as_mut_ptr(), out.len(), params.as_ptr()) } == 1;
    // SAFETY: made above.
    unsafe { EVP_KDF_CTX_free(ctx) };
    ok.then_some(out)
}

/// A derivation through a key context, the inputs given by `set`; the copy of the context
/// must derive the same.
fn through_pkey(i: &Inputs<'_>, set: impl Fn(*mut Ctx) -> bool) -> Option<Vec<u8>> {
    let name = if i.hkdf { c"HKDF" } else { c"TLS1-PRF" };
    // SAFETY: the default context; a static name.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    assert!(!ctx.is_null());
    // SAFETY: the context.
    assert_eq!(unsafe { EVP_PKEY_derive_init(ctx) }, 1);
    let mut result = None;
    if set(ctx) {
        let mut out = vec![0u8; i.len()];
        let mut len = out.len();
        // SAFETY: the context; the buffer.
        if unsafe { EVP_PKEY_derive(ctx, out.as_mut_ptr(), &raw mut len) } == 1 {
            out.truncate(len);
            // SAFETY: the context.
            let dup = unsafe { EVP_PKEY_CTX_dup(ctx) };
            // A KDF whose context holds empty octets can't copy them (nor can OpenSSL's).
            if !dup.is_null() {
                let mut again = vec![0u8; i.len()];
                let mut len2 = again.len();
                // SAFETY: the copy; the buffer.
                assert_eq!(
                    unsafe { EVP_PKEY_derive(dup, again.as_mut_ptr(), &raw mut len2) },
                    1
                );
                again.truncate(len2);
                assert_eq!(again, out);
                // SAFETY: made above.
                unsafe { EVP_PKEY_CTX_free(dup) };
            }
            result = Some(out);
        }
    }
    // SAFETY: made above.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    result
}

/// Sends ctrl strings made of `rest` (NUL-separated `name`, `value` pairs) to a context.
fn ctrl_strings(kdf: &CStr, rest: &[u8]) {
    // SAFETY: the default context; a static name.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), kdf.as_ptr(), ptr::null()) };
    // SAFETY: the context.
    unsafe { EVP_PKEY_derive_init(ctx) };
    let mut parts = rest.split(|&b| b == 0);
    while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
        let (Ok(n), Ok(v)) = (CString::new(n), CString::new(v)) else {
            continue;
        };
        // SAFETY: the context; the strings.
        unsafe { EVP_PKEY_CTX_ctrl_str(ctx, n.as_ptr(), v.as_ptr()) };
    }
    let mut len = 0usize;
    // The size only: a scrypt context given large costs would take long to derive.
    // SAFETY: the context.
    unsafe { EVP_PKEY_derive(ctx, ptr::null_mut(), &raw mut len) };
    // SAFETY: made above.
    unsafe { EVP_PKEY_CTX_free(ctx) };
}

fuzz_target!(|data: &[u8]| {
    let [kind, choice, outlen, keylen, saltlen, rest @ ..] = data else {
        return;
    };
    let (md, mdsize) = DIGESTS[usize::from(*choice) % DIGESTS.len()];
    let keylen = usize::from(*keylen).min(rest.len());
    let (key, rest) = rest.split_at(keylen);
    let saltlen = usize::from(*saltlen).min(rest.len());
    let (salt, rest) = rest.split_at(saltlen);
    let infolen = rest.len().min(64);
    let (info, rest) = rest.split_at(infolen);
    let i = Inputs {
        hkdf: kind % 2 == 0,
        md,
        mdsize,
        mode: usize::from(kind / 2) % 3,
        key,
        salt,
        info,
        outlen: usize::from(*outlen % 128) + 1,
    };
    let expected = direct(&i);
    // SAFETY: a static name.
    let mdp = unsafe { EVP_get_digestbyname(md.as_ptr()) };
    let half = i.info.len() / 2;
    let typed = through_pkey(&i, |c| {
        // SAFETY: the context; the digest; the input's octets, for each.
        unsafe {
            if i.hkdf {
                EVP_PKEY_CTX_set_hkdf_md(c, mdp) == 1
                    && EVP_PKEY_CTX_set1_hkdf_key(c, i.key.as_ptr(), int(i.key.len())) == 1
                    && EVP_PKEY_CTX_set1_hkdf_salt(c, i.salt.as_ptr(), int(i.salt.len())) == 1
                    && EVP_PKEY_CTX_add1_hkdf_info(c, i.info.as_ptr(), int(half)) == 1
                    && EVP_PKEY_CTX_add1_hkdf_info(
                        c,
                        i.info.as_ptr().wrapping_add(half),
                        int(i.info.len() - half),
                    ) == 1
                    && EVP_PKEY_CTX_set_hkdf_mode(c, int(i.mode)) == 1
            } else {
                EVP_PKEY_CTX_set_tls1_prf_md(c, mdp) == 1
                    && EVP_PKEY_CTX_set1_tls1_prf_secret(c, i.key.as_ptr(), int(i.key.len())) == 1
                    && EVP_PKEY_CTX_add1_tls1_prf_seed(c, i.info.as_ptr(), int(i.info.len())) == 1
            }
        }
    });
    assert_eq!(typed, expected);
    let ctrls = through_pkey(&i, |c| {
        let ctrl = |cmd: c_int, d: &[u8]| {
            // SAFETY: the context; the command's octets.
            unsafe {
                EVP_PKEY_CTX_ctrl(
                    c,
                    -1,
                    DERIVE,
                    cmd,
                    int(d.len()),
                    d.as_ptr().cast_mut().cast(),
                ) == 1
            }
        };
        let md_ok = |cmd: c_int| {
            // SAFETY: the context; the digest.
            unsafe { EVP_PKEY_CTX_ctrl(c, -1, DERIVE, cmd, 0, mdp.cast_mut()) == 1 }
        };
        if i.hkdf {
            let mode = CString::new(MODES[i.mode].to_bytes()).unwrap_or_default();
            md_ok(HKDF_MD)
                && ctrl(HKDF_KEY, i.key)
                && ctrl(HKDF_SALT, i.salt)
                && ctrl(HKDF_INFO, i.info)
                // SAFETY: the context; static strings.
                && unsafe { EVP_PKEY_CTX_ctrl_str(c, c"mode".as_ptr(), mode.as_ptr()) } == 1
        } else {
            md_ok(TLS_MD) && ctrl(TLS_SECRET, i.key) && ctrl(TLS_SEED, i.info)
        }
    });
    assert_eq!(ctrls, expected);
    let strings = through_pkey(&i, |c| {
        let set = |n: &CStr, v: &CStr| {
            // SAFETY: the context; the strings.
            unsafe { EVP_PKEY_CTX_ctrl_str(c, n.as_ptr(), v.as_ptr()) == 1 }
        };
        if i.hkdf {
            let mode = CString::new(MODES[i.mode].to_bytes()).unwrap_or_default();
            set(c"md", md)
                && set(c"hexkey", &hex(i.key))
                && set(c"hexsalt", &hex(i.salt))
                && set(c"hexinfo", &hex(i.info))
                && set(c"mode", &mode)
        } else {
            set(c"md", md) && set(c"hexsecret", &hex(i.key)) && set(c"hexseed", &hex(i.info))
        }
    });
    // Empty octets in hexadecimal are an empty string, which the parameter parser takes too.
    assert_eq!(strings, expected);
    for kdf in [c"HKDF", c"TLS1-PRF", c"SCRYPT"] {
        ctrl_strings(kdf, rest);
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
