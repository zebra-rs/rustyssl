//! Fuzzes the text database and SRP's verifier files on untrusted input: the input read as a
//! TXT_DB of 1 to 6 fields, written back (which must read again to the same rows), and indexed
//! by its first field; the input as an SRP verifier file (`SRP_VBASE_init`, through a file) and
//! its users looked up; and the input's lines as SRP base64 groups and salts for
//! `SRP_create_verifier`. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use std::ffi::CString;
use std::io::Write as _;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    BIGNUM, BIO, BIO_CTRL_INFO, BIO_METHOD, OPENSSL_STACK, OPENSSL_STRING, SRP_VBASE, SRP_gN_cache,
    SRP_user_pwd, TXT_DB,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn TXT_DB_read(in_: *mut BIO, num: c_int) -> *mut TXT_DB;
    fn TXT_DB_write(out: *mut BIO, db: *mut TXT_DB) -> c_long;
    fn TXT_DB_create_index(
        db: *mut TXT_DB,
        field: c_int,
        qual: Option<unsafe extern "C" fn(*mut OPENSSL_STRING) -> c_int>,
        hash: Option<unsafe extern "C" fn(*const c_void) -> c_ulong>,
        cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
    ) -> c_int;
    fn TXT_DB_get_by_index(db: *mut TXT_DB, idx: c_int, value: *mut OPENSSL_STRING) -> *mut OPENSSL_STRING;
    fn TXT_DB_free(db: *mut TXT_DB);
    fn SRP_VBASE_new(seed_key: *mut c_char) -> *mut SRP_VBASE;
    fn SRP_VBASE_init(vb: *mut SRP_VBASE, verifier_file: *mut c_char) -> c_int;
    fn SRP_VBASE_get1_by_user(vb: *mut SRP_VBASE, username: *mut c_char) -> *mut SRP_user_pwd;
    fn SRP_VBASE_free(vb: *mut SRP_VBASE);
    fn SRP_user_pwd_free(user_pwd: *mut SRP_user_pwd);
    fn SRP_create_verifier(
        user: *const c_char,
        pass: *const c_char,
        salt: *mut *mut c_char,
        verifier: *mut *mut c_char,
        n: *const c_char,
        g: *const c_char,
    ) -> *mut c_char;
    fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> c_int;
    fn OPENSSL_sk_value(st: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_pop(st: *mut OPENSSL_STACK) -> *mut c_void;
    fn BN_free(a: *mut BIGNUM);
    fn OPENSSL_LH_strhash(c: *const c_char) -> c_ulong;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// The first field's hash, for an index.
unsafe extern "C" fn hash0(a: *const c_void) -> c_ulong {
    // SAFETY: a row of at least one field.
    unsafe { OPENSSL_LH_strhash(a.cast::<*const c_char>().read()) }
}

/// The first fields compared.
unsafe extern "C" fn cmp0(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: a row of at least one field.
    let x = unsafe { a.cast::<*const c_char>().read() };
    // SAFETY: as above.
    let y = unsafe { b.cast::<*const c_char>().read() };
    // SAFETY: the fields, NUL-terminated.
    let (x, y) = (unsafe { core::ffi::CStr::from_ptr(x) }, unsafe { core::ffi::CStr::from_ptr(y) });
    match x.cmp(y) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// The rows of a database, each its fields' text.
fn rows(db: *mut TXT_DB) -> Vec<Vec<Vec<u8>>> {
    // SAFETY: a live database.
    let d = unsafe { &*db };
    let nf = usize::try_from(d.num_fields).unwrap_or(0);
    // SAFETY: its list.
    let n = unsafe { OPENSSL_sk_num(d.data.cast()) };
    (0..n)
        .map(|i| {
            // SAFETY: an index in range.
            let r: *mut *mut c_char = unsafe { OPENSSL_sk_value(d.data.cast(), i) }.cast();
            (0..nf)
                .map(|k| {
                    // SAFETY: field `k` of the row, a string.
                    unsafe { core::ffi::CStr::from_ptr(r.add(k).read()) }.to_bytes().to_vec()
                })
                .collect()
        })
        .collect()
}

/// The database written to a memory BIO, as octets.
fn written(db: *mut TXT_DB) -> Vec<u8> {
    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: live objects.
    let n = unsafe { TXT_DB_write(out, db) };
    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: BIO_get_mem_data on a memory BIO.
    let len = unsafe { BIO_ctrl(out, BIO_CTRL_INFO, 0, (&raw mut p).cast()) };
    let v = if n >= 0 && len > 0 && !p.is_null() {
        // SAFETY: the BIO's `len` octets.
        unsafe { core::slice::from_raw_parts(p.cast::<u8>(), usize::try_from(len).unwrap_or(0)) }.to_vec()
    } else {
        Vec::new()
    };
    // SAFETY: made here.
    unsafe { BIO_free(out) };
    v
}

/// The database `text` reads to, with `num` fields.
fn read(text: &[u8], num: c_int) -> *mut TXT_DB {
    let len = c_int::try_from(text.len()).unwrap_or(0);
    // SAFETY: the octets, which outlive the BIO.
    let b = unsafe { BIO_new_mem_buf(text.as_ptr().cast(), len) };
    // SAFETY: the BIO.
    let db = unsafe { TXT_DB_read(b, num) };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    db
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, text)) = data.split_first() else { return };
    let num = c_int::from(first % 6) + 1;
    let db = read(text, num);
    if !db.is_null() {
        let before = rows(db);
        let out = written(db);
        let again = read(&out, num);
        // The format can't hold a field ending in a backslash (the tab after it reads as
        // escaped) or a row starting with '#' (a comment): only other rows must read back.
        let representable = before.iter().all(|r| {
            r.first().is_none_or(|f| f.first() != Some(&b'#')) && r.iter().all(|f| f.last() != Some(&b'\\'))
        });
        if representable {
            assert!(!again.is_null(), "a written database that doesn't read");
            assert_eq!(rows(again), before, "the rows changed");
        }
        if !again.is_null() {
            // SAFETY: made here.
            unsafe { TXT_DB_free(again) };
        }
        // SAFETY: live objects; the functions read the first field.
        if unsafe { TXT_DB_create_index(db, 0, None, Some(hash0), Some(cmp0)) } == 1 {
            // SAFETY: the database's rows, which index 0 holds.
            let n = unsafe { OPENSSL_sk_num((*db).data.cast()) };
            for i in 0..n {
                // SAFETY: an index in range.
                let r = unsafe { OPENSSL_sk_value((*db).data.cast(), i) }.cast();
                // SAFETY: live objects.
                let found = unsafe { TXT_DB_get_by_index(db, 0, r) };
                assert!(!found.is_null(), "an indexed row not found");
            }
        }
        // SAFETY: made here.
        unsafe { TXT_DB_free(db) };
    }

    // The input as a verifier file.
    let path = std::env::temp_dir().join(format!("txt_db_read_{}.txt", std::process::id()));
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(text);
    }
    if let Ok(p) = CString::new(path.to_string_lossy().into_owned()) {
        // SAFETY: a static key.
        let vb = unsafe { SRP_VBASE_new(c"seed".as_ptr().cast_mut()) };
        // SAFETY: the base; the path.
        unsafe { SRP_VBASE_init(vb, p.as_ptr().cast_mut()) };
        for name in [c"alice", c"bob", c""] {
            // SAFETY: the base; a static name.
            let u = unsafe { SRP_VBASE_get1_by_user(vb, name.as_ptr().cast_mut()) };
            // SAFETY: made here, or NULL.
            unsafe { SRP_user_pwd_free(u) };
        }
        // SRP_VBASE_free frees the group cache's list but not its entries, as OpenSSL does: the
        // users SRP_VBASE_get1_by_user returns borrow their g and N, so they must outlive the
        // base. Ours are freed, so the entries go here (or LeakSanitizer reports them).
        // SAFETY: the base made above, or NULL.
        if let Some(v) = unsafe { vb.as_ref() } {
            let cache: *mut OPENSSL_STACK = v.gN_cache.cast();
            loop {
                // SAFETY: the base's cache, which holds only entries.
                let e: *mut SRP_gN_cache = unsafe { OPENSSL_sk_pop(cache) }.cast();
                // SAFETY: an entry the cache held, or NULL when it's empty.
                let Some(entry) = (unsafe { e.as_ref() }) else { break };
                // SAFETY: the entry's string and number, then the entry, each freed once.
                unsafe {
                    CRYPTO_free(entry.b64_bn.cast(), ptr::null(), 0);
                    BN_free(entry.bn);
                    CRYPTO_free(e.cast(), ptr::null(), 0);
                }
            }
        }
        // SAFETY: made here.
        unsafe { SRP_VBASE_free(vb) };
    }
    let _ = std::fs::remove_file(&path);

    // Lines as SRP base64: group, generator, salt.
    let mut lines = text.split(|&c| c == b'\n').map(|l| CString::new(l.iter().copied().filter(|&c| c != 0).collect::<Vec<u8>>()));
    if let (Some(Ok(n)), Some(Ok(g)), Some(Ok(s))) = (lines.next(), lines.next(), lines.next()) {
        let mut salt = s.into_raw();
        let mut verifier: *mut c_char = ptr::null_mut();
        // SAFETY: strings; the slots.
        unsafe { SRP_create_verifier(c"u".as_ptr(), c"p".as_ptr(), &raw mut salt, &raw mut verifier, n.as_ptr(), g.as_ptr()) };
        // SAFETY: the library's verifier, or NULL.
        unsafe { CRYPTO_free(verifier.cast(), ptr::null(), 0) };
        // SAFETY: the salt given (a salt is only made when none is given).
        drop(unsafe { CString::from_raw(salt) });
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
