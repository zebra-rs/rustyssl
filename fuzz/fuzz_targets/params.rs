//! Fuzzes parameters (`OSSL_PARAM`) through the C ABI, with data buffers of exactly
//! `data_size` octets (so an access past one is an ASan error): every getter over arbitrary
//! typed octets, and a value read must be stored back to the same octets; every setter of
//! arbitrary values, and a value stored must read back unchanged; string copies into buffers of
//! every size (a double stored in an integer reads back if a double can hold it); and `OSSL_PARAM_dup`, `OSSL_PARAM_merge`, and `OSSL_PARAM_BLD` over arrays of
//! arbitrary keys and data, which must copy every parameter faithfully.

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_REAL,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OSSL_PARAM_get_int32(p: *const OSSL_PARAM, val: *mut i32) -> c_int;
    fn OSSL_PARAM_get_uint32(p: *const OSSL_PARAM, val: *mut u32) -> c_int;
    fn OSSL_PARAM_get_int64(p: *const OSSL_PARAM, val: *mut i64) -> c_int;
    fn OSSL_PARAM_get_uint64(p: *const OSSL_PARAM, val: *mut u64) -> c_int;
    fn OSSL_PARAM_get_double(p: *const OSSL_PARAM, val: *mut f64) -> c_int;
    fn OSSL_PARAM_set_int32(p: *mut OSSL_PARAM, val: i32) -> c_int;
    fn OSSL_PARAM_set_uint32(p: *mut OSSL_PARAM, val: u32) -> c_int;
    fn OSSL_PARAM_set_int64(p: *mut OSSL_PARAM, val: i64) -> c_int;
    fn OSSL_PARAM_set_uint64(p: *mut OSSL_PARAM, val: u64) -> c_int;
    fn OSSL_PARAM_set_double(p: *mut OSSL_PARAM, val: f64) -> c_int;
    fn OSSL_PARAM_get_utf8_string(p: *const OSSL_PARAM, val: *mut *mut c_char, max_len: usize) -> c_int;
    fn OSSL_PARAM_get_octet_string(p: *const OSSL_PARAM, val: *mut *mut c_void, max_len: usize, used: *mut usize) -> c_int;
    fn OSSL_PARAM_set_utf8_string(p: *mut OSSL_PARAM, val: *const c_char) -> c_int;
    fn OSSL_PARAM_set_octet_string(p: *mut OSSL_PARAM, val: *const c_void, len: usize) -> c_int;
    fn OSSL_PARAM_dup(p: *const OSSL_PARAM) -> *mut OSSL_PARAM;
    fn OSSL_PARAM_merge(p1: *const OSSL_PARAM, p2: *const OSSL_PARAM) -> *mut OSSL_PARAM;
    fn OSSL_PARAM_free(p: *mut OSSL_PARAM);
    fn OSSL_PARAM_BLD_new() -> *mut c_void;
    fn OSSL_PARAM_BLD_free(bld: *mut c_void);
    fn OSSL_PARAM_BLD_push_int64(bld: *mut c_void, key: *const c_char, num: i64) -> c_int;
    fn OSSL_PARAM_BLD_push_double(bld: *mut c_void, key: *const c_char, num: f64) -> c_int;
    fn OSSL_PARAM_BLD_push_utf8_string(bld: *mut c_void, key: *const c_char, buf: *const c_char, bsize: usize) -> c_int;
    fn OSSL_PARAM_BLD_push_octet_string(bld: *mut c_void, key: *const c_char, buf: *const c_void, bsize: usize) -> c_int;
    fn OSSL_PARAM_BLD_to_param(bld: *mut c_void) -> *mut OSSL_PARAM;
    fn ERR_clear_error();
}

const TYPES: [c_int; 5] =
    [OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_REAL, OSSL_PARAM_UTF8_STRING, OSSL_PARAM_OCTET_STRING];

/// The fuzzer's input, consumed from the front.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.0.len());
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a.to_vec()
    }

    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        b.iter_mut().for_each(|x| *x = self.byte());
        u64::from_le_bytes(b)
    }
}

/// A parameter of `data_type` over `data` (all of it).
fn param(data_type: c_int, data: &mut [u8]) -> OSSL_PARAM {
    OSSL_PARAM {
        key: c"k".as_ptr(),
        data_type: data_type.cast_unsigned(),
        data: data.as_mut_ptr().cast(),
        data_size: data.len(),
        return_size: 0,
    }
}

/// Reads typed octets every way; integers read back must be stored back the same.
fn getters(data_type: c_int, data: &[u8]) {
    if data_type == OSSL_PARAM_INTEGER && data.is_empty() {
        return;
    }
    let mut buf = data.to_vec().into_boxed_slice();
    let p = param(data_type, &mut buf);
    let (mut a, mut b, mut c, mut d, mut e) = (0i32, 0u32, 0i64, 0u64, 0f64);
    // SAFETY: `p`'s data is `buf`, of `data_size` octets.
    let ra = unsafe { OSSL_PARAM_get_int32(&p, &mut a) };
    // SAFETY: as above.
    let rb = unsafe { OSSL_PARAM_get_uint32(&p, &mut b) };
    // SAFETY: as above.
    let rc = unsafe { OSSL_PARAM_get_int64(&p, &mut c) };
    // SAFETY: as above.
    let rd = unsafe { OSSL_PARAM_get_uint64(&p, &mut d) };
    // SAFETY: as above.
    unsafe { OSSL_PARAM_get_double(&p, &mut e) };
    if ra == 1 && rc == 1 {
        assert_eq!(i64::from(a), c);
    }
    if rb == 1 && rd == 1 {
        assert_eq!(u64::from(b), d);
    }
    if data_type == OSSL_PARAM_REAL {
        return;
    }
    let mut back = vec![0xaau8; data.len()].into_boxed_slice();
    if rc == 1 {
        let mut q = param(data_type, &mut back);
        // SAFETY: `q`'s data is `back`, of `data_size` octets.
        assert_eq!(unsafe { OSSL_PARAM_set_int64(&mut q, c) }, 1);
        assert_eq!(&*back, data, "int64 {c} stored back differently");
    }
    if rd == 1 {
        let mut q = param(data_type, &mut back);
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PARAM_set_uint64(&mut q, d) }, 1);
        assert_eq!(&*back, data, "uint64 {d} stored back differently");
    }
}

/// Stores `v` every way into a parameter of `data_type` and `size` octets; what's stored must
/// read back.
fn setters(data_type: c_int, size: usize, v: u64) {
    if data_type == OSSL_PARAM_INTEGER && size == 0 {
        return;
    }
    let mut buf = vec![0xaau8; size].into_boxed_slice();
    let signed = v.cast_signed();
    let mut p = param(data_type, &mut buf);
    // SAFETY: `p`'s data is `buf`, of `data_size` octets.
    if unsafe { OSSL_PARAM_set_int64(&mut p, signed) } == 1 {
        let mut got = 0i64;
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PARAM_get_int64(&p, &mut got) }, 1);
        assert_eq!(got, signed);
    }
    let mut p = param(data_type, &mut buf);
    // SAFETY: as above.
    if unsafe { OSSL_PARAM_set_uint64(&mut p, v) } == 1 {
        let mut got = 0u64;
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PARAM_get_uint64(&p, &mut got) }, 1);
        assert_eq!(got, v);
    }
    let low = (v as u32).cast_signed();
    let mut p = param(data_type, &mut buf);
    // SAFETY: as above.
    if unsafe { OSSL_PARAM_set_int32(&mut p, low) } == 1 {
        let mut got = 0i32;
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PARAM_get_int32(&p, &mut got) }, 1);
        assert_eq!(got, low);
    }
    let mut p = param(data_type, &mut buf);
    // SAFETY: as above.
    if unsafe { OSSL_PARAM_set_uint32(&mut p, low.cast_unsigned()) } == 1 {
        let mut got = 0u32;
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PARAM_get_uint32(&p, &mut got) }, 1);
        assert_eq!(got, low.cast_unsigned());
    }
    let real = f64::from_bits(v);
    let mut p = param(data_type, &mut buf);
    // SAFETY: as above.
    if unsafe { OSSL_PARAM_set_double(&mut p, real) } == 1 && !real.is_nan() {
        // An integer may hold more than a double reads back exactly.
        let mut got = 0f64;
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_get_double(&p, &mut got) } == 1 {
            assert_eq!(got, real);
        }
    }
}

/// Copies a string of `data` (as a parameter of `size` octets) into a buffer of `max`, and
/// stores it into a parameter of `max` octets.
fn strings(utf8: bool, data: &[u8], max: usize) {
    let data_type = if utf8 { OSSL_PARAM_UTF8_STRING } else { OSSL_PARAM_OCTET_STRING };
    let mut src = data.to_vec().into_boxed_slice();
    let p = param(data_type, &mut src);
    let mut out = vec![0u8; max].into_boxed_slice();
    let mut used = 0;
    let mut to = out.as_mut_ptr().cast::<c_void>();
    let r = if utf8 {
        // SAFETY: `to` has `max` octets.
        unsafe { OSSL_PARAM_get_utf8_string(&p, ptr::from_mut(&mut to).cast(), max) }
    } else {
        // SAFETY: as above.
        unsafe { OSSL_PARAM_get_octet_string(&p, &mut to, max, &mut used) }
    };
    if r == 1 {
        assert_eq!(&out[..data.len()], data);
    }
    let mut dest = vec![0u8; max].into_boxed_slice();
    let mut q = param(data_type, &mut dest);
    if utf8 {
        let text: Vec<u8> = data.iter().copied().take_while(|&c| c != 0).collect();
        let text = CString::new(text).unwrap();
        // SAFETY: `q`'s data is `dest`, of `max` octets.
        if unsafe { OSSL_PARAM_set_utf8_string(&mut q, text.as_ptr()) } == 1 {
            assert_eq!(&dest[..text.count_bytes()], text.as_bytes());
        }
    } else {
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_set_octet_string(&mut q, data.as_ptr().cast(), data.len()) } == 1 {
            assert_eq!(&dest[..data.len()], data);
        }
    }
}

/// The parameters of an array, up to its end.
fn entries<'a>(p: *const OSSL_PARAM) -> Vec<&'a OSSL_PARAM> {
    let mut v = Vec::new();
    let mut at = p;
    loop {
        // SAFETY: an array ended by a NULL key.
        let q = unsafe { &*at };
        if q.key.is_null() {
            return v;
        }
        v.push(q);
        at = at.wrapping_add(1);
    }
}

/// The octets of a parameter's data.
fn octets(p: &OSSL_PARAM) -> &[u8] {
    // SAFETY: the data holds `data_size` octets.
    unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) }
}

/// Duplicates, merges, and builds arrays of the input's parameters.
fn arrays(input: &mut Input<'_>) {
    let n = usize::from(input.byte() % 12);
    let mut keys = Vec::new();
    let mut datas = Vec::new();
    for _ in 0..n {
        let klen = usize::from(input.byte() % 4) + 1;
        let k = input.take(klen);
        keys.push(CString::new(k.into_iter().map(|c| c.max(1)).collect::<Vec<_>>()).unwrap());
        let len = usize::from(input.byte() % 20);
        datas.push(input.take(len).into_boxed_slice());
    }
    let mut params: Vec<OSSL_PARAM> = keys
        .iter()
        .zip(datas.iter_mut())
        .map(|(k, d)| OSSL_PARAM {
            key: k.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING.cast_unsigned(),
            data: d.as_mut_ptr().cast(),
            data_size: d.len(),
            return_size: 7,
        })
        .collect();
    params.push(OSSL_PARAM { key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0 });

    // SAFETY: an array ended by a NULL key, whose data holds `data_size` octets.
    let dup = unsafe { OSSL_PARAM_dup(params.as_ptr()) };
    let copies = entries(dup);
    assert_eq!(copies.len(), n);
    for (copy, orig) in copies.iter().zip(&params) {
        assert_eq!(copy.key, orig.key);
        assert_eq!(copy.return_size, 7);
        assert_eq!(octets(copy), octets(orig));
    }
    let half = n / 2;
    let mut second: Vec<OSSL_PARAM> = params[half..].to_vec();
    params[half] = *params.last().unwrap();
    // SAFETY: both arrays end with a NULL key.
    let merged = unsafe { OSSL_PARAM_merge(params.as_ptr(), second.as_mut_ptr()) };
    if !merged.is_null() {
        let m = entries(merged);
        assert!(m.len() <= n);
        for w in m.windows(2) {
            // SAFETY: keys are strings.
            let (a, b) = unsafe { (CStr::from_ptr(w[0].key), CStr::from_ptr(w[1].key)) };
            let (a, b) = (a.to_bytes().to_ascii_lowercase(), b.to_bytes().to_ascii_lowercase());
            assert!(a <= b);
        }
    }
    // SAFETY: from dup and merge.
    unsafe { OSSL_PARAM_free(merged) };
    // SAFETY: as above.
    unsafe { OSSL_PARAM_free(dup) };

    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    let mut expect = Vec::new();
    for (k, d) in keys.iter().zip(&datas) {
        let r = match input.byte() % 4 {
            0 => {
                let v = input.u64().cast_signed();
                expect.push(v.to_ne_bytes().to_vec());
                // SAFETY: a live builder and a key that outlives the array.
                unsafe { OSSL_PARAM_BLD_push_int64(bld, k.as_ptr(), v) }
            }
            1 => {
                let v = f64::from_bits(input.u64());
                expect.push(v.to_ne_bytes().to_vec());
                // SAFETY: as above.
                unsafe { OSSL_PARAM_BLD_push_double(bld, k.as_ptr(), v) }
            }
            2 if !d.is_empty() => {
                expect.push(d.to_vec());
                // SAFETY: as above; `d` holds `bsize` octets.
                unsafe { OSSL_PARAM_BLD_push_utf8_string(bld, k.as_ptr(), d.as_ptr().cast(), d.len()) }
            }
            _ => {
                expect.push(d.to_vec());
                // SAFETY: as above.
                unsafe { OSSL_PARAM_BLD_push_octet_string(bld, k.as_ptr(), d.as_ptr().cast(), d.len()) }
            }
        };
        assert_eq!(r, 1);
    }
    // SAFETY: a live builder whose strings are live.
    let built = unsafe { OSSL_PARAM_BLD_to_param(bld) };
    let b = entries(built);
    assert_eq!(b.len(), n);
    for ((p, e), k) in b.iter().zip(&expect).zip(&keys) {
        assert_eq!(p.key, k.as_ptr());
        assert_eq!(octets(p), &e[..]);
    }
    // SAFETY: from the builder.
    unsafe { OSSL_PARAM_free(built) };
    // SAFETY: the builder.
    unsafe { OSSL_PARAM_BLD_free(bld) };
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    while !input.0.is_empty() {
        match input.byte() % 4 {
            0 => {
                let t = TYPES[usize::from(input.byte()) % TYPES.len()];
                let len = usize::from(input.byte() % 20);
                let octets = input.take(len);
                getters(t, &octets);
            }
            1 => {
                let t = TYPES[usize::from(input.byte()) % TYPES.len()];
                let size = usize::from(input.byte() % 20);
                let v = input.u64();
                setters(t, size, v);
            }
            2 => {
                let utf8 = input.byte() % 2 == 0;
                let max = usize::from(input.byte() % 20);
                let len = usize::from(input.byte() % 20);
                let octets = input.take(len);
                strings(utf8, &octets, max);
            }
            _ => arrays(&mut input),
        }
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
    }
});
