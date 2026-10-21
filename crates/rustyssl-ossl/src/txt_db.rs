//! `TXT_DB`, the text database behind `ca`'s index file (and `ocsp`'s, `srp`'s).
//!
//! Rows are read and changed through their indices in the database's `data` stack. Indexes
//! hash and compare one field (optionally ignoring leading `0`s, as the CA's serial-number
//! index does), and may count only the rows whose first field starts with a given byte (the
//! CA's name index counts only valid, `V`, rows).

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use crate::abi::{OPENSSL_STACK, OPENSSL_STRING, TXT_DB};
use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, string_at};

/// An owned `TXT_DB`, freed with `TXT_DB_free`.
pub struct TxtDb(core::ptr::NonNull<TXT_DB>);

impl Drop for TxtDb {
    fn drop(&mut self) {
        // SAFETY: the database is owned here and freed once.
        unsafe { ffi::TXT_DB_free(self.0.as_ptr()) };
    }
}

/// How an index hashes and compares its field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IndexKind {
    /// The field as it is.
    Plain,
    /// The field without its leading `0`s (`index_serial_hash`/`_cmp` of `apps.c`).
    NoLeadingZeros,
}

/// The number of fields an index may be on.
const MAX_FIELDS: usize = 8;

/// The field `F` of the row at `p`, as a C string pointer (NULL if absent).
///
/// # Safety
/// `p` is a row of a database of more than `F` fields: an array of C-string pointers.
unsafe fn field_of<const F: usize>(p: *const c_void) -> *const c_char {
    // SAFETY: per the contract, the row holds at least F + 1 pointers.
    let row = unsafe { core::slice::from_raw_parts(p.cast::<*const c_char>(), F + 1) };
    row.get(F).copied().unwrap_or(core::ptr::null())
}

/// The bytes of a C string, past its leading `0`s when `strip`.
///
/// # Safety
/// `s` is NULL or a valid C string.
unsafe fn key<'a>(s: *const c_char, strip: bool) -> &'a [u8] {
    if s.is_null() {
        return &[];
    }
    // SAFETY: s is a valid C string per the contract.
    let b = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes();
    if strip {
        let n = b.iter().take_while(|&&c| c == b'0').count();
        b.get(n..).unwrap_or_default()
    } else {
        b
    }
}

unsafe extern "C" fn hash_field<const F: usize, const STRIP: bool>(p: *const c_void) -> c_ulong {
    // SAFETY: the library passes a row of this database (the index is on field F).
    let s = unsafe { field_of::<F>(p) };
    // SAFETY: s is the row's C string.
    let k = unsafe { key(s, STRIP) };
    let Ok(c) = std::ffi::CString::new(k) else {
        return 0;
    };
    // SAFETY: a valid C string.
    unsafe { ffi::OPENSSL_LH_strhash(c.as_ptr()) }
}

unsafe extern "C" fn cmp_field<const F: usize, const STRIP: bool>(
    a: *const c_void,
    b: *const c_void,
) -> c_int {
    // SAFETY: as in hash_field, for both rows.
    let fa = unsafe { field_of::<F>(a) };
    // SAFETY: as above.
    let fb = unsafe { field_of::<F>(b) };
    // SAFETY: the rows' C strings.
    let x = unsafe { key(fa, STRIP) };
    // SAFETY: as above.
    let y = unsafe { key(fb, STRIP) };
    match x.cmp(y) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

unsafe extern "C" fn qual_valid(row: *mut OPENSSL_STRING) -> c_int {
    // SAFETY: the library passes a row; its first field is a C string.
    let first = unsafe { field_of::<0>(row.cast_const().cast()) };
    // SAFETY: first is a C string of at least its NUL.
    c_int::from(!first.is_null() && unsafe { *first.cast::<u8>() } == b'V')
}

type HashFn = unsafe extern "C" fn(*const c_void) -> c_ulong;
type CmpFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

macro_rules! fns {
    ($f:expr, $strip:expr, $($n:literal)*) => {
        match ($f, $strip) {
            $(
                ($n, false) => (hash_field::<$n, false> as HashFn, cmp_field::<$n, false> as CmpFn),
                ($n, true) => (hash_field::<$n, true> as HashFn, cmp_field::<$n, true> as CmpFn),
            )*
            _ => return false,
        }
    };
}

impl TxtDb {
    fn db(&self) -> &TXT_DB {
        // SAFETY: the database is live and owned by self.
        unsafe { self.0.as_ref() }
    }

    fn data(&self) -> *mut OPENSSL_STACK {
        self.db().data.cast()
    }

    /// `TXT_DB_read(bio, num)`.
    pub fn read(bio: &Bio, num: c_int) -> Option<Self> {
        // SAFETY: the BIO is live.
        core::ptr::NonNull::new(unsafe { ffi::TXT_DB_read(bio.as_ptr(), num) }).map(Self)
    }

    /// `TXT_DB_write(bio, db)`: what it returns.
    pub fn write(&self, bio: &Bio) -> c_long {
        // SAFETY: both are live.
        unsafe { ffi::TXT_DB_write(bio.as_ptr(), self.0.as_ptr()) }
    }

    /// The number of fields of each row.
    pub fn num_fields(&self) -> usize {
        usize::try_from(self.db().num_fields).unwrap_or(0)
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        // SAFETY: the stack is live.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.data()) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The row at `i`, as pointers.
    fn row_ptr(&self, i: usize) -> Option<*mut *mut c_char> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: the stack is live; out-of-range gives NULL.
        let p = unsafe { ffi::OPENSSL_sk_value(self.data(), i) }.cast::<*mut c_char>();
        (!p.is_null()).then_some(p)
    }

    /// The `num_fields + 1` slots of a row (its fields, then its block's end).
    ///
    /// The slice is used at once and not kept: the database owns the row.
    #[allow(clippy::mut_from_ref)]
    fn slots(&self, row: *mut *mut c_char) -> &mut [*mut c_char] {
        // SAFETY: every row of the database (and every row alloc_row makes) has num_fields
        // pointers and one more slot; the CLI uses the database from one thread, and no two
        // of these slices are alive at once.
        unsafe { core::slice::from_raw_parts_mut(row, self.num_fields() + 1) }
    }

    /// Field `f` of row `i` (`None` for NULL), as bytes.
    pub fn field(&self, i: usize, f: usize) -> Option<Vec<u8>> {
        if f >= self.num_fields() {
            return None;
        }
        let row = self.row_ptr(i)?;
        let s = self.slots(row).get(f).copied()?;
        if s.is_null() {
            return None;
        }
        // SAFETY: s is the row's C string.
        Some(unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes().to_vec())
    }

    /// Field `f` of row `i`, as text (lossy).
    pub fn field_str(&self, i: usize, f: usize) -> Option<String> {
        self.field(i, f)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// Sets the first character of field `f` of row `i` in place (`row[f][0] = c`), when the
    /// field is a non-empty string (`srp` marks rows so).
    pub fn set_first_char(&self, i: usize, f: usize, c: u8) {
        if f >= self.num_fields() {
            return;
        }
        let Some(row) = self.row_ptr(i) else {
            return;
        };
        let Some(&p) = self.slots(row).get(f) else {
            return;
        };
        // SAFETY: a non-NULL field is a NUL-terminated string the database owns, at least one
        // byte long; a non-empty one is written in place, as the C code does.
        if !p.is_null() && unsafe { *p } != 0 {
            // SAFETY: as above.
            unsafe { *p = c_char::from_ne_bytes([c]) };
        }
    }

    /// Replaces field `f` of row `i` with `value` (a new allocation the database frees),
    /// freeing the old one if the database allocated it apart from the row's block.
    pub fn set_field(&self, i: usize, f: usize, value: Option<&str>) -> bool {
        if f >= self.num_fields() {
            return false;
        }
        let Some(row) = self.row_ptr(i) else {
            return false;
        };
        let new = match value {
            Some(v) => {
                let Some(c) = cstring(v) else {
                    return false;
                };
                // SAFETY: a valid C string; the copy belongs to the database.
                let p = unsafe { ffi::CRYPTO_strdup(c.as_ptr(), c"txt_db".as_ptr(), 0) };
                if p.is_null() {
                    return false;
                }
                p
            }
            None => core::ptr::null_mut(),
        };
        let n = self.num_fields();
        let slots = self.slots(row);
        // The block's end is NULL for a row inserted by the program, whose fields are each
        // allocated.
        let (Some(&old), Some(&max)) = (slots.get(f), slots.get(n)) else {
            return false;
        };
        let in_block =
            !max.is_null() && (old.cast_const() >= row.cast_const().cast::<c_char>()) && old <= max;
        if !old.is_null() && !in_block {
            crate::util::openssl_free(old.cast());
        }
        if let Some(slot) = self.slots(row).get_mut(f) {
            *slot = new;
        }
        true
    }

    /// `TXT_DB_create_index(db, field, qual, hash, cmp)`, with `valid_only` the qualifier
    /// that counts only rows whose first field starts with `V`.
    pub fn create_index(&self, field: usize, kind: IndexKind, valid_only: bool) -> bool {
        if field >= MAX_FIELDS || field >= self.num_fields() {
            return false;
        }
        let (h, c) = fns!(field, kind == IndexKind::NoLeadingZeros, 0 1 2 3 4 5 6 7);
        let Ok(f) = c_int::try_from(field) else {
            return false;
        };
        let qual: Option<unsafe extern "C" fn(*mut OPENSSL_STRING) -> c_int> =
            valid_only.then_some(qual_valid);
        // SAFETY: the database is live; the functions read only the indexed field of rows
        // of this database, which has more fields than `field`.
        unsafe { ffi::TXT_DB_create_index(self.0.as_ptr(), f, qual, Some(h), Some(c)) == 1 }
    }

    /// The database's `error`, `arg1`, and `arg2`.
    pub fn error(&self) -> (c_long, c_long, c_long) {
        let d = self.db();
        (d.error, d.arg1, d.arg2)
    }

    /// Builds a row of C strings the library can own (`OPENSSL_malloc`ed, NULL-terminated),
    /// or `None`.
    fn alloc_row(&self, fields: &[Option<&str>]) -> Option<*mut *mut c_char> {
        let n = self.num_fields();
        if fields.len() != n {
            return None;
        }
        let size = core::mem::size_of::<*mut c_char>().checked_mul(n + 1)?;
        // SAFETY: a plain allocation of `size` bytes.
        let row = unsafe { ffi::CRYPTO_malloc(size, c"txt_db".as_ptr(), 0) }.cast::<*mut c_char>();
        if row.is_null() {
            return None;
        }
        for (k, v) in fields.iter().chain(core::iter::once(&None)).enumerate() {
            let p = match v.and_then(cstring) {
                // SAFETY: a valid C string; the copy belongs to the row.
                Some(c) => unsafe { ffi::CRYPTO_strdup(c.as_ptr(), c"txt_db".as_ptr(), 0) },
                None => core::ptr::null_mut(),
            };
            if let Some(slot) = self.slots(row).get_mut(k) {
                *slot = p;
            }
        }
        Some(row)
    }

    /// Frees a row made by `alloc_row`.
    fn free_row(&self, row: *mut *mut c_char) {
        let n = self.num_fields();
        for &p in self.slots(row).iter().take(n) {
            crate::util::openssl_free(p.cast());
        }
        crate::util::openssl_free(row.cast());
    }

    /// `TXT_DB_get_by_index(db, field, row)`: the index of the matching row.
    pub fn get_by_index(&self, field: usize, fields: &[Option<&str>]) -> Option<usize> {
        let f = c_int::try_from(field).ok()?;
        let row = self.alloc_row(fields)?;
        // SAFETY: the database is live; row has num_fields strings.
        let found = unsafe { ffi::TXT_DB_get_by_index(self.0.as_ptr(), f, row.cast()) };
        self.free_row(row);
        if found.is_null() {
            return None;
        }
        (0..self.len()).find(|&i| self.row_ptr(i) == Some(found.cast()))
    }

    /// `TXT_DB_insert(db, row)`: whether it was inserted (the database then owns it).
    pub fn insert(&self, fields: &[Option<&str>]) -> bool {
        let Some(row) = self.alloc_row(fields) else {
            return false;
        };
        // SAFETY: the database is live; on success it takes the row.
        if unsafe { ffi::TXT_DB_insert(self.0.as_ptr(), row.cast()) } == 1 {
            true
        } else {
            self.free_row(row);
            false
        }
    }
}

/// The old `CONF` API's configuration (`CONF_load`), freed with `CONF_free`.
pub struct LegacyConf(core::ptr::NonNull<crate::abi::lhash_st_CONF_VALUE>);

impl Drop for LegacyConf {
    fn drop(&mut self) {
        // SAFETY: owned here and freed once.
        unsafe { ffi::CONF_free(self.0.as_ptr()) };
    }
}

impl LegacyConf {
    /// `CONF_load(NULL, file, &eline)`: the configuration, or the error line `eline` as the
    /// call left it (0 if it didn't set it).
    pub fn load(file: &str) -> Result<Self, c_long> {
        let Some(f) = cstring(file) else {
            return Err(0);
        };
        let mut eline: c_long = 0;
        // SAFETY: a valid C string; eline is a valid out-pointer.
        let p = unsafe { ffi::CONF_load(core::ptr::null_mut(), f.as_ptr(), &mut eline) };
        core::ptr::NonNull::new(p).map(Self).ok_or(eline)
    }

    /// `CONF_get_section(conf, section)`: its (name, value) pairs, in order.
    pub fn get_section(&self, section: &str) -> Vec<(String, String)> {
        let Some(s) = cstring(section) else {
            return Vec::new();
        };
        // SAFETY: the configuration is live; the stack is owned by it.
        let sk =
            unsafe { ffi::CONF_get_section(self.0.as_ptr(), s.as_ptr()) }.cast::<OPENSSL_STACK>();
        let mut out = Vec::new();
        // SAFETY: sk is NULL or live.
        let n = unsafe { ffi::OPENSSL_sk_num(sk) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each member is a CONF_VALUE.
            let v = unsafe { ffi::OPENSSL_sk_value(sk, i) }.cast::<crate::abi::CONF_VALUE>();
            if v.is_null() {
                continue;
            }
            // SAFETY: v is live (owned by the configuration).
            let cv = unsafe { &*v };
            out.push((
                string_at(cv.name).unwrap_or_default(),
                string_at(cv.value).unwrap_or_default(),
            ));
        }
        out
    }
}
