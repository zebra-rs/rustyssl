//! SRP verifier files for `openssl srp` (`apps/srp.c`): the `TXT_DB` of an index file (its
//! rows as the C code edits them), `SRP_create_verifier`, and the apps' password prompt.

use core::ffi::{c_char, c_int, c_long};

use crate::abi::{DB_srpinfo, OPENSSL_STACK, OPENSSL_STRING, TXT_DB};
use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, openssl_free, string_at};

/// The number of fields of a verifier file's row (`DB_NUMBER`).
pub const FIELDS: usize = 6;
const _: () = assert!(DB_srpinfo == 5);

/// An owned `TXT_DB`.
pub struct TxtDb(core::ptr::NonNull<TXT_DB>);

impl Drop for TxtDb {
    fn drop(&mut self) {
        // SAFETY: owned, freed once (with every row and field the library knows of).
        unsafe { ffi::TXT_DB_free(self.0.as_ptr()) };
    }
}

impl TxtDb {
    /// `TXT_DB_read(in, num)`.
    pub fn read(bio: &Bio, num: c_int) -> Option<Self> {
        // SAFETY: the BIO is live.
        core::ptr::NonNull::new(unsafe { ffi::TXT_DB_read(bio.as_ptr(), num) }).map(Self)
    }

    fn data(&self) -> *mut OPENSSL_STACK {
        // SAFETY: the database is live (public layout).
        unsafe { (*self.0.as_ptr()).data }.cast()
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        // SAFETY: a live stack.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.data()) }).unwrap_or(0)
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Row `i`'s field pointers.
    fn row(&self, i: usize) -> Option<&[*mut c_char]> {
        let p = self.row_ptr(i)?;
        // SAFETY: a row of a database read or inserted with FIELDS fields holds that many
        // field pointers, owned by the database (which `self` borrows).
        Some(unsafe { core::slice::from_raw_parts(p, FIELDS) })
    }

    /// Row `i`'s field pointers, to change.
    fn row_mut(&mut self, i: usize) -> Option<&mut [*mut c_char]> {
        let p = self.row_ptr(i)?;
        // SAFETY: as above; `self` is borrowed mutably.
        Some(unsafe { core::slice::from_raw_parts_mut(p, FIELDS) })
    }

    fn row_ptr(&self, i: usize) -> Option<*mut OPENSSL_STRING> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: a live stack; the index is checked by the library (NULL if out of range).
        let r = unsafe { ffi::OPENSSL_sk_value(self.data(), i) }.cast::<OPENSSL_STRING>();
        (!r.is_null()).then_some(r)
    }

    /// Field `f` of row `i` (`None` for a NULL field or no such row).
    pub fn field(&self, i: usize, f: usize) -> Option<String> {
        if f >= FIELDS {
            return None;
        }
        string_at(*self.row(i)?.get(f)?)
    }

    /// Row `i`'s fields.
    pub fn fields(&self, i: usize) -> [Option<String>; FIELDS] {
        core::array::from_fn(|f| self.field(i, f))
    }

    /// Sets the first character of field `f` of row `i` (`row[f][0] = c`).
    pub fn set_first_char(&mut self, i: usize, f: usize, c: u8) {
        if f >= FIELDS {
            return;
        }
        let Some(&p) = self.row(i).and_then(|r| r.get(f)) else {
            return;
        };
        // SAFETY: a non-NULL field is a NUL-terminated string at least as long as its first
        // character; a non-empty one is written in place, as the C code does.
        if !p.is_null() && unsafe { *p } != 0 {
            // SAFETY: as above.
            unsafe { *p = c_char::from_ne_bytes([c]) };
        }
    }

    /// Replaces field `f` of row `i` with a copy of `value` (the old value is left to the
    /// database, as the C code leaves it).
    pub fn set_field(&mut self, i: usize, f: usize, value: &str) -> bool {
        if f >= FIELDS {
            return false;
        }
        let Some(slot) = self.row_mut(i).and_then(|r| r.get_mut(f)) else {
            return false;
        };
        let p = crate::ssl::c_strdup(value);
        if p.is_null() {
            return false;
        }
        // The database frees the new one.
        *slot = p;
        true
    }

    /// `TXT_DB_insert` of a new row: `Err` with the database's error number if it fails.
    pub fn insert(&self, fields: &[Option<String>; FIELDS]) -> Result<(), c_long> {
        let size = (FIELDS + 1) * core::mem::size_of::<*mut c_char>();
        // SAFETY: a plain allocation, filled below.
        let row =
            unsafe { ffi::CRYPTO_malloc(size, c"rustyssl-ossl".as_ptr(), 0) }.cast::<*mut c_char>();
        if row.is_null() {
            return Err(0);
        }
        // SAFETY: row has room for FIELDS + 1 pointers, ours until inserted.
        let slots = unsafe { core::slice::from_raw_parts_mut(row, FIELDS + 1) };
        for (slot, v) in slots.iter_mut().zip(fields.iter()) {
            *slot = v
                .as_deref()
                .map_or(core::ptr::null_mut(), crate::ssl::c_strdup);
        }
        // The end marker of a new row.
        if let Some(last) = slots.get_mut(FIELDS) {
            *last = core::ptr::null_mut();
        }
        // SAFETY: the database takes the row on success.
        if unsafe { ffi::TXT_DB_insert(self.0.as_ptr(), row) } != 0 {
            return Ok(());
        }
        // SAFETY: the database is live (public layout).
        let e = unsafe { (*self.0.as_ptr()).error };
        for &p in slots.iter() {
            openssl_free(p.cast());
        }
        openssl_free(row.cast());
        Err(e)
    }

    /// `TXT_DB_write(out, db)`.
    pub fn write(&self, out: &Bio) -> c_long {
        // SAFETY: both are live.
        unsafe { ffi::TXT_DB_write(out.as_ptr(), self.0.as_ptr()) }
    }
}

/// `SRP_create_verifier(user, pass, &salt, &verifier, N, g)`: the gN id, the salt and the
/// verifier; `salt` given is used (and returned), else a new one is made.
pub fn create_verifier(
    user: &str,
    pass: &[u8],
    salt: Option<&str>,
    n: Option<&str>,
    g: Option<&str>,
) -> Option<(String, String, String)> {
    let u = cstring(user)?;
    let mut pw = pass.to_vec();
    pw.push(0);
    let c = |s: Option<&str>| match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    };
    let (sc, nc, gc) = (c(salt)?, c(n)?, c(g)?);
    let mut s: *mut c_char = sc
        .as_ref()
        .map_or(core::ptr::null_mut(), |s| s.as_ptr().cast_mut());
    let mut v: *mut c_char = core::ptr::null_mut();
    let p = |x: &Option<std::ffi::CString>| x.as_ref().map_or(core::ptr::null(), |x| x.as_ptr());
    // SAFETY: the strings are valid or NULL; a given salt is only read; a new salt and the
    // verifier are the caller's to free.
    let id = unsafe {
        ffi::SRP_create_verifier(
            u.as_ptr(),
            pw.as_ptr().cast(),
            &mut s,
            &mut v,
            p(&nc),
            p(&gc),
        )
    };
    // SAFETY: pw is valid for its length.
    unsafe { ffi::OPENSSL_cleanse(pw.as_mut_ptr().cast(), pw.len()) };
    let new_salt = sc.is_none();
    let salt_out = string_at(s);
    if new_salt {
        openssl_free(s.cast());
    }
    let verifier = string_at(v);
    openssl_free(v.cast());
    let id = string_at(id)?;
    Some((id, salt_out?, verifier?))
}

/// `SRP_get_default_gN(id)` is not NULL.
pub fn default_gn_exists(id: Option<&str>) -> bool {
    let c = match id {
        Some(s) => match cstring(s) {
            Some(c) => Some(c),
            None => return false,
        },
        None => None,
    };
    // SAFETY: a valid C string or NULL; the result is static.
    !unsafe { ffi::SRP_get_default_gN(c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())) }
        .is_null()
}

/// `password_callback(buf, size, verify, &{password, prompt_info})` of `apps_ui.c`: the
/// password read (or given), or the callback's result (<= 0) on failure.
pub fn password_callback(
    size: usize,
    verify: bool,
    password: Option<&str>,
    prompt_info: Option<&str>,
) -> Result<Vec<u8>, c_int> {
    let data = crate::ui::Passphrase::new(password, prompt_info);
    let mut buf = vec![0u8; size.max(1)];
    let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
    // SAFETY: buf is writable for n bytes; data is a live PW_CB_DATA.
    let len = unsafe {
        crate::ui::password_callback(
            buf.as_mut_ptr().cast(),
            n,
            c_int::from(verify),
            data.as_ptr(),
        )
    };
    let Ok(l) = usize::try_from(len) else {
        return Err(len);
    };
    let out = buf.get(..l.min(buf.len())).unwrap_or_default().to_vec();
    // SAFETY: buf is valid for its length.
    unsafe { ffi::OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) };
    if l == 0 {
        return Err(0);
    }
    Ok(out)
}

/// `perror(s)`.
pub fn perror(s: &str) {
    if let Some(c) = cstring(s) {
        // SAFETY: a valid C string.
        unsafe { libc::perror(c.as_ptr()) };
    }
}
