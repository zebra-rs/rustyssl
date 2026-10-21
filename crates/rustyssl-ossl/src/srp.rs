//! SRP verifier files for `openssl srp` (`apps/srp.c`): `SRP_create_verifier` and the apps'
//! password prompt (the index file is a [`TxtDb`]).

use core::ffi::{c_char, c_int};

use crate::abi::DB_srpinfo;
use crate::ffi;
pub use crate::txt_db::TxtDb;
use crate::util::{cstring, openssl_free, string_at};

/// The number of fields of a verifier file's row (`DB_NUMBER`).
pub const FIELDS: usize = 6;
const _: () = assert!(DB_srpinfo == 5);

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
