//! The text database (`TXT_DB_*`, `crypto/txt_db/txt_db.c`): the `openssl ca` index and the SRP
//! verifier file. Rows are lines of tab-separated fields (a backslash before a tab keeps the tab
//! in the field); a line starting with `#` is a comment.
//!
//! `TXT_DB` is public in `txt_db.h` and applications read it (`db->data`, `db->error`), so it and
//! its rows keep OpenSSL's layout: a row is one `CRYPTO_malloc` block of `num + 1` field
//! pointers followed by the fields' text, its last pointer marking the block's end (or NULL for
//! a row the application built, whose fields are then each its own allocation).

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr;

use rustyssl_abi::{
    BIO, DB_ERROR_INDEX_CLASH, DB_ERROR_INDEX_OUT_OF_RANGE, DB_ERROR_MALLOC, DB_ERROR_NO_INDEX,
    DB_ERROR_OK, DB_ERROR_WRONG_NUM_FIELDS, ERR_LIB_CRYPTO, OPENSSL_LH_COMPFUNC,
    OPENSSL_LH_HASHFUNC, OPENSSL_LHASH, OPENSSL_STACK, OPENSSL_STRING, TXT_DB,
};

use crate::bio::{BIO_gets, BIO_write};
use crate::ffi::ffi_export;
use crate::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_retrieve,
};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value,
};

/// `BUFSIZE`: how much more of a line each read takes.
const BUFSIZE: usize = 512;

/// A row's qualifier, as `TXT_DB_create_index` takes it.
type Qual = Option<unsafe extern "C" fn(*mut OPENSSL_STRING) -> c_int>;

/// The database's list of rows.
fn rows(db: &TXT_DB) -> *mut OPENSSL_STACK {
    db.data.cast()
}

/// The row at `i` of the database's list.
///
/// # Safety
/// `db` is a live database and `i` in range.
unsafe fn row(db: &TXT_DB, i: c_int) -> *mut OPENSSL_STRING {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_value(rows(db), i) }.cast()
}

/// The index of field `i` (NULL if none).
///
/// # Safety
/// `db` is a live database; `0 <= i < num_fields`.
unsafe fn index_at(db: &TXT_DB, i: usize) -> *mut OPENSSL_LHASH {
    // SAFETY: the caller's guarantee: `index` holds `num_fields` slots.
    let slot = unsafe { db.index.add(i) };
    // SAFETY: as above.
    unsafe { slot.read() }.cast()
}

/// The qualifier of field `i`'s index (None if none).
///
/// # Safety
/// As for [`index_at`].
unsafe fn qual_at(db: &TXT_DB, i: usize) -> Qual {
    // SAFETY: the caller's guarantee: `qual` holds `num_fields` slots.
    let slot = unsafe { db.qual.add(i) };
    // SAFETY: as above.
    unsafe { slot.read() }
}

/// Whether the row is excluded from field `i`'s index by its qualifier.
///
/// # Safety
/// As for [`index_at`]; `r` is a live row. The qualifier is the application's, called with no
/// lock held.
unsafe fn excluded(db: &TXT_DB, i: usize, r: *mut OPENSSL_STRING) -> bool {
    // SAFETY: the caller's guarantee.
    match unsafe { qual_at(db, i) } {
        // SAFETY: the application's qualifier, with its row.
        Some(q) => (unsafe { q(r) }) == 0,
        None => false,
    }
}

/// Frees a row that `TXT_DB_read` made: one block.
///
/// # Safety
/// `r` is NULL or a row from [`parse_row`], not used after.
unsafe fn free_read_row(r: *mut OPENSSL_STRING) {
    // SAFETY: the caller's guarantee.
    unsafe { mem::release(r.cast()) };
}

/// Frees a half-made database: its list (and the rows read so far, which OpenSSL leaks), its
/// index and qualifier arrays, and itself.
///
/// # Safety
/// `ret` is a block from [`TXT_DB_read`] whose `data` is NULL or a list of read rows.
unsafe fn free_partial(ret: *mut TXT_DB) {
    // SAFETY: the caller's guarantee.
    let Some(db) = (unsafe { ret.as_mut() }) else {
        return;
    };
    let list = rows(db);
    // SAFETY: the list, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: an index in range.
        let r = unsafe { row(db, i) };
        // SAFETY: a row the reader made.
        unsafe { free_read_row(r) };
    }
    // SAFETY: the list, or NULL.
    unsafe { OPENSSL_sk_free(list) };
    // SAFETY: the arrays, or NULL.
    unsafe { mem::release(db.index.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(db.qual.cast()) };
    // SAFETY: the database itself.
    unsafe { mem::release(ret.cast()) };
}

/// The fields of one line (without its newline), as `TXT_DB_read` splits it: the field area's
/// octets, each field's start in it, and where the last field ended; or None if the line
/// hasn't exactly `num` fields.
fn split_fields(line: &[u8], num: usize) -> Option<(Vec<u8>, Vec<usize>, usize)> {
    let mut area: Vec<u8> = vec![0; line.len().saturating_add(1)];
    let mut w = 0usize;
    let mut starts = vec![0usize];
    let mut f = 0usize;
    let mut esc = false;
    let put = |area: &mut Vec<u8>, w: &mut usize, c: u8| {
        if let Some(slot) = area.get_mut(*w) {
            *slot = c;
        }
        *w = w.saturating_add(1);
    };
    while let Some(&c) = line.get(f) {
        if c == b'\t' {
            if esc {
                // The backslash before the tab is dropped and the tab kept.
                w = w.saturating_sub(1);
            } else {
                put(&mut area, &mut w, 0);
                f = f.saturating_add(1);
                if starts.len() >= num {
                    break;
                }
                starts.push(w);
                continue;
            }
        }
        esc = c == b'\\';
        put(&mut area, &mut w, c);
        f = f.saturating_add(1);
    }
    put(&mut area, &mut w, 0);
    if starts.len() != num || f < line.len() {
        return None;
    }
    area.truncate(w);
    Some((area, starts, w))
}

/// A row block for the fields: `num + 1` pointers, then the fields' text; the pointers point
/// into it, the last at the end of the last field. NULL if allocation fails.
fn parse_row(
    area: &[u8],
    starts: &[usize],
    end: usize,
    num: usize,
    line_size: usize,
) -> *mut OPENSSL_STRING {
    let Some(add) = num
        .checked_add(1)
        .and_then(|n| n.checked_mul(size_of::<*mut c_char>()))
    else {
        return ptr::null_mut();
    };
    let Some(total) = add.checked_add(line_size) else {
        return ptr::null_mut();
    };
    let block = mem::alloc(total);
    if block.is_null() {
        return ptr::null_mut();
    }
    let pp: *mut *mut c_char = block.cast();
    // SAFETY: `add` octets into the block of `total`.
    let text: *mut c_char = unsafe { block.cast::<u8>().add(add) }.cast();
    // The field area is never longer than the line with its NUL, `line_size` octets.
    let len = area.len().min(line_size);
    // SAFETY: `len` octets from the area into the block's text part, which holds `line_size`.
    unsafe { ptr::copy_nonoverlapping(area.as_ptr(), text.cast::<u8>(), len) };
    for (k, &s) in starts.iter().enumerate() {
        // SAFETY: its start within the text part.
        let start = unsafe { text.add(s.min(line_size)) };
        // SAFETY: field `k` of the `num + 1` pointer slots.
        let slot = unsafe { pp.add(k) };
        // SAFETY: as above.
        unsafe { slot.write(start) };
    }
    // SAFETY: the end within the text part.
    let stop = unsafe { text.add(end.min(line_size)) };
    // SAFETY: the last pointer slot (`starts.len() == num`).
    let slot = unsafe { pp.add(num) };
    // SAFETY: as above.
    unsafe { slot.write(stop) };
    pp.cast()
}

ffi_export! {
    /// Reads a database of `num` fields a row from `in_`: each line not starting with `#` is a
    /// row, which must have exactly `num` fields (else the whole read fails). NULL on failure
    /// (including `num <= 0`, as OpenSSL's zero-size allocations fail).
    ///
    /// As OpenSSL's, a line is read in pieces of 511, 512, 512, ... octets: a comment line
    /// longer than the first piece goes on as a row, and an octet NUL drops the rest of its
    /// piece.
    ///
    /// # Safety
    /// `in_` is a live BIO.
    pub unsafe extern "C" fn TXT_DB_read(in_: *mut BIO, num: c_int) -> *mut TXT_DB
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let ret: *mut TXT_DB = mem::alloc(size_of::<TXT_DB>()).cast();
        if ret.is_null() {
            return ptr::null_mut();
        }
        // A negative count makes OpenSSL's sizes wrap, so the allocations fail.
        let n = usize::try_from(num).unwrap_or(usize::MAX);
        // SAFETY: the block made for the database.
        unsafe {
            ret.write(TXT_DB {
                num_fields: num,
                data: ptr::null_mut(),
                index: ptr::null_mut(),
                qual: ptr::null_mut(),
                error: 0,
                arg1: 0,
                arg2: 0,
                arg_row: ptr::null_mut(),
            })
        };
        // SAFETY: as above.
        let db = unsafe { &mut *ret };
        // SAFETY: no preconditions.
        db.data = unsafe { OPENSSL_sk_new_null() }.cast();
        if db.data.is_null() {
            // SAFETY: made here.
            unsafe { free_partial(ret) };
            return ptr::null_mut();
        }
        db.index = mem::alloc(n.saturating_mul(size_of::<*mut c_void>())).cast();
        if db.index.is_null() {
            // SAFETY: made here.
            unsafe { free_partial(ret) };
            return ptr::null_mut();
        }
        db.qual = mem::alloc(n.saturating_mul(size_of::<Qual>())).cast();
        if db.qual.is_null() {
            // SAFETY: made here.
            unsafe { free_partial(ret) };
            return ptr::null_mut();
        }
        for i in 0..n {
            // SAFETY: slot `i` of the `n` the arrays hold.
            let slot = unsafe { db.index.add(i) };
            // SAFETY: as above.
            unsafe { slot.write(ptr::null_mut()) };
            // SAFETY: as above.
            let slot = unsafe { db.qual.add(i) };
            // SAFETY: as above.
            unsafe { slot.write(None) };
        }
        let mut size = BUFSIZE;
        let mut buf: Vec<u8> = vec![0; size];
        let mut offset = 0usize;
        loop {
            if offset != 0 {
                size = size.saturating_add(BUFSIZE);
                buf.resize(size, 0);
            }
            let room = c_int::try_from(size.saturating_sub(offset)).unwrap_or(c_int::MAX);
            let Some(piece) = buf.get_mut(offset..) else { break };
            if let Some(first) = piece.first_mut() {
                *first = 0;
            }
            // SAFETY: the BIO; the buffer's `size - offset` octets from `offset`.
            unsafe { BIO_gets(in_, piece.as_mut_ptr().cast(), room) };
            let got = piece.iter().position(|&b| b == 0).unwrap_or(piece.len());
            if got == 0 {
                break;
            }
            if offset == 0 && buf.first() == Some(&b'#') {
                continue;
            }
            offset = offset.saturating_add(got);
            if buf.get(offset.wrapping_sub(1)) != Some(&b'\n') {
                continue;
            }
            let line_size = offset;
            offset = 0;
            let line = buf.get(..line_size.saturating_sub(1)).unwrap_or(&[]);
            let Some((area, starts, end)) = split_fields(line, n) else {
                db.error = c_long::from(DB_ERROR_WRONG_NUM_FIELDS);
                // SAFETY: made here; the rows read so far.
                unsafe { free_partial(ret) };
                return ptr::null_mut();
            };
            let r = parse_row(&area, &starts, end, n, line_size);
            if r.is_null() {
                // SAFETY: as above.
                unsafe { free_partial(ret) };
                return ptr::null_mut();
            }
            // SAFETY: the list; the row, taken.
            if unsafe { OPENSSL_sk_push(rows(db), r.cast()) } == 0 {
                // SAFETY: the row, not taken.
                unsafe { free_read_row(r) };
                // SAFETY: as above.
                unsafe { free_partial(ret) };
                return ptr::null_mut();
            }
        }
        ret
    }
}

ffi_export! {
    /// The row whose field `idx` matches `value`'s through that field's index, or NULL (with
    /// `db->error` set: out of range, no index, or OK when nothing matches).
    ///
    /// # Safety
    /// `db` is a live database (as in OpenSSL, NULL crashes); `value` a row the index's hash and
    /// comparison accept.
    pub unsafe extern "C" fn TXT_DB_get_by_index(db: *mut TXT_DB, idx: c_int, value: *mut OPENSSL_STRING) -> *mut OPENSSL_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { db.as_mut() }) else { return ptr::null_mut() };
        // A negative index is refused too (OpenSSL reads before the array).
        let Some(i) = usize::try_from(idx).ok().filter(|_| idx < d.num_fields) else {
            d.error = c_long::from(DB_ERROR_INDEX_OUT_OF_RANGE);
            return ptr::null_mut();
        };
        // SAFETY: an index in range.
        let lh = unsafe { index_at(d, i) };
        if lh.is_null() {
            d.error = c_long::from(DB_ERROR_NO_INDEX);
            return ptr::null_mut();
        }
        // SAFETY: the index; the caller's row. Its hash and comparison are the application's.
        let r = unsafe { OPENSSL_LH_retrieve(lh, value.cast()) };
        // SAFETY: the caller's database, again (the callbacks may have used it).
        if let Some(d) = unsafe { db.as_mut() } {
            d.error = c_long::from(DB_ERROR_OK);
        }
        r.cast()
    }
}

ffi_export! {
    /// Indexes field `field` with `hash` and `cmp` over the rows `qual` accepts (all with
    /// NULL), replacing any index it had: 1, or 0 with `db->error` set (on a clash, `arg1` and
    /// `arg2` are the clashing rows' numbers).
    ///
    /// # Safety
    /// `db` is a live database (as in OpenSSL, NULL crashes); the functions are NULL or valid
    /// for its rows.
    pub unsafe extern "C" fn TXT_DB_create_index(db: *mut TXT_DB, field: c_int, qual: Qual, hash: OPENSSL_LH_HASHFUNC, cmp: OPENSSL_LH_COMPFUNC) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { db.as_mut() }) else { return 0 };
        let Some(fi) = usize::try_from(field).ok().filter(|_| field < d.num_fields) else {
            d.error = c_long::from(DB_ERROR_INDEX_OUT_OF_RANGE);
            return 0;
        };
        // SAFETY: the caller's functions.
        let idx = unsafe { OPENSSL_LH_new(hash, cmp) };
        if idx.is_null() {
            d.error = c_long::from(DB_ERROR_MALLOC);
            return 0;
        }
        let list = rows(d);
        // SAFETY: the list.
        let n = unsafe { OPENSSL_sk_num(list) };
        for i in 0..n {
            // SAFETY: an index in range.
            let r: *mut OPENSSL_STRING = unsafe { OPENSSL_sk_value(list, i) }.cast();
            if let Some(q) = qual
                // SAFETY: the application's qualifier, with a row of the database.
                && unsafe { q(r) } == 0
            {
                continue;
            }
            // SAFETY: the new index; the row.
            let k = unsafe { OPENSSL_LH_insert(idx, r.cast()) };
            // SAFETY: the caller's database, again (the callbacks may have used it).
            let Some(d) = (unsafe { db.as_mut() }) else { return 0 };
            if !k.is_null() {
                d.error = c_long::from(DB_ERROR_INDEX_CLASH);
                // SAFETY: the list; the row it held, compared by address.
                d.arg1 = c_long::from(unsafe { OPENSSL_sk_find(list, k) });
                d.arg2 = c_long::from(i);
                // SAFETY: made here.
                unsafe { OPENSSL_LH_free(idx) };
                return 0;
            }
            // SAFETY: as above.
            if unsafe { OPENSSL_LH_retrieve(idx, r.cast()) }.is_null() {
                // SAFETY: as above.
                if let Some(d) = unsafe { db.as_mut() } {
                    d.error = c_long::from(DB_ERROR_MALLOC);
                }
                // SAFETY: made here.
                unsafe { OPENSSL_LH_free(idx) };
                return 0;
            }
        }
        // SAFETY: as above.
        let Some(d) = (unsafe { db.as_mut() }) else { return 0 };
        // SAFETY: the field's index slot, in range.
        let slot = unsafe { d.index.add(fi) };
        // SAFETY: the old index, or NULL.
        let old = unsafe { slot.read() };
        // SAFETY: the old index, or NULL.
        unsafe { OPENSSL_LH_free(old.cast()) };
        // SAFETY: the slot; the new index, taken.
        unsafe { slot.write(idx.cast()) };
        // SAFETY: the field's qualifier slot, in range.
        let slot = unsafe { d.qual.add(fi) };
        // SAFETY: as above.
        unsafe { slot.write(qual) };
        1
    }
}

ffi_export! {
    /// Writes the rows to `out` as lines of tab-separated fields (a tab in a field written as
    /// backslash-tab; a NULL field as empty): the octets written, or -1.
    ///
    /// # Safety
    /// `out` is a live BIO; `db` a live database (as in OpenSSL, NULL crashes).
    pub unsafe extern "C" fn TXT_DB_write(out: *mut BIO, db: *mut TXT_DB) -> c_long
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { db.as_ref() }) else { return -1 };
        let Ok(nn) = usize::try_from(d.num_fields) else { return -1 };
        let list = rows(d);
        // SAFETY: the list.
        let n = unsafe { OPENSSL_sk_num(list) };
        let mut tot: c_long = 0;
        for i in 0..n {
            // SAFETY: an index in range.
            let pp: *mut *mut c_char = unsafe { OPENSSL_sk_value(list, i) }.cast();
            let mut line: Vec<u8> = Vec::new();
            for j in 0..nn {
                // SAFETY: field `j` of the row's `num_fields`.
                let slot = unsafe { pp.add(j) };
                // SAFETY: as above.
                let f = unsafe { slot.read() };
                if !f.is_null() {
                    // SAFETY: a field, NUL-terminated.
                    let text = unsafe { core::ffi::CStr::from_ptr(f) }.to_bytes();
                    for &c in text {
                        if c == b'\t' {
                            line.push(b'\\');
                        }
                        line.push(c);
                    }
                }
                line.push(b'\t');
            }
            // OpenSSL's buffer is sized by an int; a line that can't fit it fails.
            if c_int::try_from(line.len()).is_err() {
                return -1;
            }
            // The last tab becomes the newline (no fields: no line, where OpenSSL writes before
            // its buffer).
            let Some(last) = line.last_mut() else { return -1 };
            *last = b'\n';
            let Ok(j) = c_int::try_from(line.len()) else { return -1 };
            // SAFETY: the BIO; the line's octets.
            if unsafe { BIO_write(out, line.as_ptr().cast(), j) } != j {
                return -1;
            }
            tot = tot.saturating_add(c_long::from(j));
        }
        tot
    }
}

ffi_export! {
    /// Adds a row (taken; `num_fields + 1` pointers, the last NULL for one built by the
    /// application) to the database and its indexes: 1, or 0 with `db->error` set (on a clash,
    /// `arg1` is the field and `arg_row` the row it clashed with).
    ///
    /// # Safety
    /// `db` is a live database (as in OpenSSL, NULL crashes); `row` a live row.
    pub unsafe extern "C" fn TXT_DB_insert(db: *mut TXT_DB, row: *mut OPENSSL_STRING) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { db.as_mut() }) else { return 0 };
        let nf = usize::try_from(d.num_fields).unwrap_or(0);
        for i in 0..nf {
            // SAFETY: an index in range.
            let lh = unsafe { index_at(d, i) };
            // SAFETY: as above; the caller's row.
            if lh.is_null() || unsafe { excluded(d, i, row) } {
                continue;
            }
            // SAFETY: the index; the row.
            let r = unsafe { OPENSSL_LH_retrieve(lh, row.cast()) };
            if !r.is_null() {
                // SAFETY: the caller's database, again (the callbacks may have used it).
                if let Some(d) = unsafe { db.as_mut() } {
                    d.error = c_long::from(DB_ERROR_INDEX_CLASH);
                    d.arg1 = c_long::try_from(i).unwrap_or(c_long::MAX);
                    d.arg_row = r.cast();
                }
                return 0;
            }
        }
        let mut done = 0usize;
        let mut ok = true;
        for i in 0..nf {
            done = i;
            // SAFETY: as above.
            let lh = unsafe { index_at(d, i) };
            // SAFETY: as above.
            if lh.is_null() || unsafe { excluded(d, i, row) } {
                continue;
            }
            // SAFETY: the index; the row.
            unsafe { OPENSSL_LH_insert(lh, row.cast()) };
            // SAFETY: as above.
            if unsafe { OPENSSL_LH_retrieve(lh, row.cast()) }.is_null() {
                ok = false;
                break;
            }
            done = i.saturating_add(1);
        }
        // SAFETY: the list; the row, taken.
        if ok && unsafe { OPENSSL_sk_push(rows(d), row.cast()) } != 0 {
            return 1;
        }
        d.error = c_long::from(DB_ERROR_MALLOC);
        // Undo the indexes before the one that failed (all of them if the push failed).
        for i in (0..done).rev() {
            // SAFETY: as above.
            let lh = unsafe { index_at(d, i) };
            // SAFETY: as above.
            if lh.is_null() || unsafe { excluded(d, i, row) } {
                continue;
            }
            // SAFETY: the index; the row.
            unsafe { OPENSSL_LH_delete(lh, row.cast()) };
        }
        0
    }
}

ffi_export! {
    /// Frees the database, its indexes, and its rows: the block of each row read, and each
    /// field outside it (a field the application replaced, or every field of a row it built).
    ///
    /// # Safety
    /// `db` is NULL or a live database, not used after; rows the application added hold
    /// `CRYPTO_malloc` fields.
    pub unsafe extern "C" fn TXT_DB_free(db: *mut TXT_DB)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { db.as_ref() }) else { return };
        let nf = usize::try_from(d.num_fields).unwrap_or(0);
        if !d.index.is_null() {
            for i in (0..nf).rev() {
                // SAFETY: an index in range.
                let h = unsafe { index_at(d, i) };
                // SAFETY: that index, or NULL.
                unsafe { OPENSSL_LH_free(h) };
            }
            // SAFETY: the array.
            unsafe { mem::release(d.index.cast()) };
        }
        // SAFETY: the array, or NULL.
        unsafe { mem::release(d.qual.cast()) };
        let list = rows(d);
        if !list.is_null() {
            // SAFETY: the list.
            let n = unsafe { OPENSSL_sk_num(list) };
            for i in (0..n).rev() {
                // SAFETY: an index in range.
                let p: *mut *mut c_char = unsafe { OPENSSL_sk_value(list, i) }.cast();
                // SAFETY: the row's end marker, after its `num_fields` fields.
                let slot = unsafe { p.add(nf) };
                // SAFETY: as above.
                let max = unsafe { slot.read() };
                let lo = p as usize;
                let hi = max as usize;
                for k in 0..nf {
                    // SAFETY: field `k` of the row.
                    let slot = unsafe { p.add(k) };
                    // SAFETY: as above.
                    let f = unsafe { slot.read() };
                    let at = f as usize;
                    if max.is_null() || at < lo || at > hi {
                        // SAFETY: a field allocated on its own (or NULL).
                        unsafe { mem::release(f.cast()) };
                    }
                }
                // SAFETY: the row itself.
                unsafe { mem::release(p.cast()) };
            }
            // SAFETY: the list.
            unsafe { OPENSSL_sk_free(list) };
        }
        // SAFETY: the database itself.
        unsafe { mem::release(db.cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::split_fields;

    #[test]
    fn splits_on_tabs_and_keeps_escaped_ones() {
        let (area, starts, end) = split_fields(b"a\tb\\\tc\td", 3).unwrap_or_default();
        assert_eq!(starts, vec![0, 2, 6]);
        assert_eq!(area, b"a\0b\tc\0d\0".to_vec());
        assert_eq!(end, 8);
    }

    #[test]
    fn needs_exactly_the_fields() {
        assert!(split_fields(b"a\tb", 3).is_none());
        assert!(split_fields(b"a\tb\tc\td", 3).is_none());
        assert!(split_fields(b"", 1).is_some());
    }
}
