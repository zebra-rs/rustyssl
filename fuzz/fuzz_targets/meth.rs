//! Fuzzes applications' methods (`EVP_PKEY_meth_*`, `EVP_PKEY_asn1_*`) and a legacy context's
//! translations of parameters, ctrls, and ctrl strings to its method's ctrl.
//!
//! The input drives a sequence of operations: adding, removing, and freeing key methods (the
//! count must follow: the built-in ones plus those added and not removed), finding ASN.1 methods
//! by a PEM name of the input's bytes (one found must have that name, ignoring case), and, with
//! a logging method added for a key type the input picks, setting and getting one parameter of
//! the input's key, type, and value, a ctrl, and a ctrl string on a context for an operation the
//! input picks. The method's ctrl, which answers what the input says, checks that octets it's
//! given are the parameter's and is called at most once per parameter. Nothing may panic or go
//! out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::cell::RefCell;
use std::ffi::CString;
use std::sync::OnceLock;

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
type Meth = c_void;

type CtrlFn = unsafe extern "C" fn(*mut Ctx, c_int, c_int, *mut c_void) -> c_int;
type CtrlStrFn = unsafe extern "C" fn(*mut Ctx, *const c_char, *const c_char) -> c_int;
type InitFn = unsafe extern "C" fn(*mut Ctx) -> c_int;
type SignFn = unsafe extern "C" fn(*mut Ctx, *mut u8, *mut usize, *const u8, usize) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut Ctx, *mut u8, *mut usize) -> c_int;
type GenFn = unsafe extern "C" fn(*mut Ctx, *mut c_void) -> c_int;

unsafe extern "C" {
    fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> *mut Meth;
    fn EVP_PKEY_meth_free(m: *mut Meth);
    fn EVP_PKEY_meth_add0(m: *const Meth) -> c_int;
    fn EVP_PKEY_meth_remove(m: *const Meth) -> c_int;
    fn EVP_PKEY_meth_get_count() -> usize;
    fn EVP_PKEY_meth_set_ctrl(m: *mut Meth, c: Option<CtrlFn>, s: Option<CtrlStrFn>);
    fn EVP_PKEY_meth_set_sign(m: *mut Meth, i: Option<InitFn>, s: Option<SignFn>);
    fn EVP_PKEY_meth_set_encrypt(m: *mut Meth, i: Option<InitFn>, s: Option<SignFn>);
    fn EVP_PKEY_meth_set_derive(m: *mut Meth, i: Option<InitFn>, s: Option<DeriveFn>);
    fn EVP_PKEY_meth_set_keygen(m: *mut Meth, i: Option<InitFn>, s: Option<GenFn>);
    fn EVP_PKEY_asn1_find_str(e: *mut *mut c_void, s: *const c_char, len: c_int) -> *const c_void;
    fn EVP_PKEY_asn1_get0_info(
        id: *mut c_int,
        base: *mut c_int,
        flags: *mut c_int,
        info: *mut *const c_char,
        pem: *mut *const c_char,
        a: *const c_void,
    ) -> c_int;
    fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut c_void) -> *mut Ctx;
    fn EVP_PKEY_CTX_free(ctx: *mut Ctx);
    fn EVP_PKEY_sign_init(ctx: *mut Ctx) -> c_int;
    fn EVP_PKEY_encrypt_init(ctx: *mut Ctx) -> c_int;
    fn EVP_PKEY_derive_init(ctx: *mut Ctx) -> c_int;
    fn EVP_PKEY_keygen_init(ctx: *mut Ctx) -> c_int;
    fn EVP_PKEY_CTX_set_params(ctx: *mut Ctx, p: *const Param) -> c_int;
    fn EVP_PKEY_CTX_get_params(ctx: *mut Ctx, p: *mut Param) -> c_int;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut Ctx,
        keytype: c_int,
        optype: c_int,
        cmd: c_int,
        p1: c_int,
        p2: *mut c_void,
    ) -> c_int;
    fn EVP_PKEY_CTX_ctrl_str(ctx: *mut Ctx, name: *const c_char, value: *const c_char) -> c_int;
    fn EVP_PKEY_CTX_str2ctrl(ctx: *mut Ctx, cmd: c_int, s: *const c_char) -> c_int;
    fn EVP_PKEY_CTX_hex2ctrl(ctx: *mut Ctx, cmd: c_int, s: *const c_char) -> c_int;
    fn OBJ_create(oid: *const c_char, sn: *const c_char, ln: *const c_char) -> c_int;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> Param;
    fn OSSL_PARAM_construct_uint(key: *const c_char, buf: *mut c_uint) -> Param;
    fn OSSL_PARAM_construct_utf8_string(key: *const c_char, buf: *mut c_char, n: usize) -> Param;
    fn OSSL_PARAM_construct_octet_string(key: *const c_char, buf: *mut c_void, n: usize) -> Param;
    fn OSSL_PARAM_construct_octet_ptr(key: *const c_char, buf: *mut *mut c_void, n: usize) -> Param;
    fn OSSL_PARAM_construct_end() -> Param;
    fn ERR_clear_error();
}

/// What the logging method's ctrl does: its answer, the octets a parameter set (which it must
/// be given if it's given octets), and how many times it ran.
struct Log {
    ret: c_int,
    octets: Option<Vec<u8>>,
    calls: usize,
}

thread_local! {
    static LOG: RefCell<Log> = const { RefCell::new(Log { ret: 1, octets: None, calls: 0 }) };
}

unsafe extern "C" fn ctrl(_: *mut Ctx, _: c_int, p1: c_int, p2: *mut c_void) -> c_int {
    LOG.with_borrow_mut(|log| {
        log.calls += 1;
        if let Some(want) = &log.octets
            && !p2.is_null()
        {
            assert_eq!(usize::try_from(p1).ok(), Some(want.len()));
            // SAFETY: the octets the translation copied, `p1` of them.
            let got = unsafe { core::slice::from_raw_parts(p2.cast::<u8>(), want.len()) };
            assert_eq!(got, &want[..]);
        }
        log.ret
    })
}

unsafe extern "C" fn ctrl_str(ctx: *mut Ctx, name: *const c_char, value: *const c_char) -> c_int {
    // SAFETY: the library's strings.
    let hex = unsafe { CStr::from_ptr(name) }.to_bytes().starts_with(b"hex");
    if hex {
        // SAFETY: the context; the value.
        unsafe { EVP_PKEY_CTX_hex2ctrl(ctx, 0x1001, value) }
    } else {
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_str2ctrl(ctx, 0x1001, value) }
    }
}

unsafe extern "C" fn sign(_: *mut Ctx, _: *mut u8, _: *mut usize, _: *const u8, _: usize) -> c_int {
    0
}

unsafe extern "C" fn derive(_: *mut Ctx, _: *mut u8, _: *mut usize) -> c_int {
    0
}

unsafe extern "C" fn keygen(_: *mut Ctx, _: *mut c_void) -> c_int {
    0
}

/// The input, read a piece at a time (zeros once it's used up).
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }

    fn signed(&mut self) -> c_int {
        c_int::from(i8::from_ne_bytes([self.byte()]))
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[usize::from(self.byte()) % items.len()]
    }

    fn bytes(&mut self) -> Vec<u8> {
        let n = usize::from(self.byte() % 24).min(self.0.len());
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a.to_vec()
    }

    fn cstring(&mut self) -> CString {
        let b: Vec<u8> = self.bytes().into_iter().filter(|&c| c != 0).collect();
        CString::new(b).unwrap_or_default()
    }
}

/// A key type of its own, for a method no translation names.
fn toy() -> c_int {
    static TOY: OnceLock<c_int> = OnceLock::new();
    // SAFETY: static strings.
    *TOY.get_or_init(|| unsafe {
        OBJ_create(c"1.3.6.1.4.1.99999.10".as_ptr(), c"FUZZTOY".as_ptr(), c"fuzz toy".as_ptr())
    })
}

const KEYS: &[&CStr] = &[
    c"distid",
    c"kdf-type",
    c"kdf-digest",
    c"kdf-outlen",
    c"kdf-ukm",
    c"cekalg",
    c"group",
    c"pad",
    c"digest",
    c"encoding",
    c"ecdh-cofactor-mode",
    c"pad-mode",
    c"saltlen",
    c"oaep-label",
    c"bits",
    c"size",
    c"secret",
    c"seed",
    c"salt",
    c"key",
    c"info",
    c"mode",
    c"n",
    c"cipher",
    c"priv",
    c"nope",
];

/// One parameter set or got through a context with the logging method.
fn param(ctx: *mut Ctx, input: &mut Input<'_>) {
    let set = input.byte() & 1 == 0;
    let key = input.pick(KEYS);
    let mut int: c_int = input.signed();
    let mut uint: c_uint = c_uint::from(input.byte());
    let mut text = [0 as c_char; 64];
    let value = input.cstring();
    for (d, &s) in text.iter_mut().zip(value.as_bytes().iter().take(63)) {
        *d = c_char::from_ne_bytes([s]);
    }
    let mut octets = input.bytes();
    let mut ptr_out: *mut c_void = ptr::null_mut();
    let kind = input.byte() % 5;
    let k = key.as_ptr();
    // SAFETY: a static key; locals that outlive the call, here and below.
    let p = unsafe {
        match kind {
            0 => OSSL_PARAM_construct_int(k, &raw mut int),
            1 => OSSL_PARAM_construct_uint(k, &raw mut uint),
            2 => OSSL_PARAM_construct_utf8_string(k, text.as_mut_ptr(), if set { 0 } else { 63 }),
            3 => {
                let n = if set { octets.len() } else { 0 };
                OSSL_PARAM_construct_octet_string(k, octets.as_mut_ptr().cast(), n)
            }
            _ => OSSL_PARAM_construct_octet_ptr(k, &raw mut ptr_out, 0),
        }
    };
    // SAFETY: no preconditions.
    let mut params = [p, unsafe { OSSL_PARAM_construct_end() }];
    LOG.with_borrow_mut(|log| {
        log.calls = 0;
        log.octets = (set && kind == 3).then(|| octets.clone());
    });
    let r = if set {
        // SAFETY: the context; the array above.
        unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
    } else {
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) }
    };
    assert!(r == 0 || r == 1);
    LOG.with_borrow(|log| assert!(log.calls <= 1));
    LOG.with_borrow_mut(|log| log.octets = None);
    // A string got is NUL-terminated within its room.
    if !set && kind == 2 {
        assert!(text.contains(&0));
    }
}

/// A context for the key type with the logging method, its operation started, driven by the
/// input; the method is removed after.
fn context(input: &mut Input<'_>) {
    let id = input.pick(&[6, 912, 408, 1172, 28, 920, 116, 1034, 1087, 855, 0]);
    let id = if id == 0 { toy() } else { id };
    // SAFETY: no preconditions.
    let m = unsafe { EVP_PKEY_meth_new(id, c_int::from(input.byte() & 2)) };
    // SAFETY: the method above; the functions.
    unsafe {
        EVP_PKEY_meth_set_ctrl(m, Some(ctrl), Some(ctrl_str));
        EVP_PKEY_meth_set_sign(m, None, Some(sign));
        EVP_PKEY_meth_set_encrypt(m, None, Some(sign));
        EVP_PKEY_meth_set_derive(m, None, Some(derive));
        EVP_PKEY_meth_set_keygen(m, None, Some(keygen));
        assert_eq!(EVP_PKEY_meth_add0(m), 1);
    }
    let ret = input.signed() % 4;
    LOG.with_borrow_mut(|log| log.ret = ret);
    // SAFETY: a key type.
    let ctx = unsafe { EVP_PKEY_CTX_new_id(id, ptr::null_mut()) };
    assert!(!ctx.is_null());
    let op = usize::from(input.byte() % 5);
    // SAFETY: the context.
    let r = unsafe {
        match op {
            0 => EVP_PKEY_sign_init(ctx),
            1 => EVP_PKEY_encrypt_init(ctx),
            2 => EVP_PKEY_derive_init(ctx),
            3 => EVP_PKEY_keygen_init(ctx),
            _ => 1,
        }
    };
    assert_eq!(r, 1);
    for _ in 0..1 + input.byte() % 4 {
        match input.byte() % 3 {
            0 => param(ctx, input),
            1 => {
                let cmd = c_int::from(input.byte()) | (c_int::from(input.byte() & 1) << 12);
                let p1 = input.signed();
                // SAFETY: the context; no pointer (the method never reads it).
                let r = unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, -1, cmd, p1, ptr::null_mut()) };
                let _ = r;
            }
            _ => {
                let name = input.cstring();
                let value = input.cstring();
                // SAFETY: the context; the strings.
                unsafe { EVP_PKEY_CTX_ctrl_str(ctx, name.as_ptr(), value.as_ptr()) };
            }
        }
    }
    // SAFETY: made above, each once.
    unsafe {
        EVP_PKEY_CTX_free(ctx);
        assert_eq!(EVP_PKEY_meth_remove(m), 1);
        EVP_PKEY_meth_free(m);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    // SAFETY: no preconditions.
    let base = unsafe { EVP_PKEY_meth_get_count() };
    let mut added: Vec<*mut Meth> = Vec::new();
    for _ in 0..1 + input.byte() % 8 {
        match input.byte() % 4 {
            0 => {
                // Key types no context here uses: the first method added for a type is the one
                // found, which would hide the logging method.
                // SAFETY: no preconditions.
                let m = unsafe { EVP_PKEY_meth_new(2000 + c_int::from(input.byte()), 0) };
                // SAFETY: the method above.
                assert_eq!(unsafe { EVP_PKEY_meth_add0(m) }, 1);
                added.push(m);
            }
            1 if !added.is_empty() => {
                let i = usize::from(input.byte()) % added.len();
                let m = added.swap_remove(i);
                // SAFETY: a method added above, removed and freed once.
                unsafe {
                    assert_eq!(EVP_PKEY_meth_remove(m), 1);
                    assert_eq!(EVP_PKEY_meth_remove(m), 0);
                    EVP_PKEY_meth_free(m);
                }
            }
            2 => {
                let name = input.bytes();
                let len = c_int::try_from(name.len()).unwrap_or(0);
                // SAFETY: `len` characters (the reference reads up to them, or a NUL).
                let a = unsafe { EVP_PKEY_asn1_find_str(ptr::null_mut(), name.as_ptr().cast(), len) };
                if !a.is_null() {
                    let mut pem: *const c_char = ptr::null();
                    // SAFETY: the method found; room for the name.
                    unsafe {
                        EVP_PKEY_asn1_get0_info(
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                            &raw mut pem,
                            a,
                        );
                    }
                    // SAFETY: the method's name.
                    let pem = unsafe { CStr::from_ptr(pem) }.to_bytes();
                    assert!(pem.eq_ignore_ascii_case(&name));
                }
            }
            _ => context(&mut input),
        }
        // SAFETY: no preconditions.
        assert_eq!(unsafe { EVP_PKEY_meth_get_count() }, base + added.len());
    }
    for m in added {
        // SAFETY: the methods added above, removed and freed once.
        unsafe {
            assert_eq!(EVP_PKEY_meth_remove(m), 1);
            EVP_PKEY_meth_free(m);
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
