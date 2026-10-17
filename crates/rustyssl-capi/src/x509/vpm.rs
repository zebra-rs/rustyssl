//! Verification parameters (`x509_vpm.c`): `X509_VERIFY_PARAM`, what a chain is verified
//! against (flags, purpose, trust, depth, security level, time, policies, and the peer's
//! hosts, email, and IP address); how one inherits from another; and the table of named
//! parameters (`default`, `pkcs7`, `smime_sign`, `ssl_client`, `ssl_server`, `code_sign`, and
//! those added).
//!
//! As OpenSSL's:
//! - A host name may end with a NUL but not hold one; an IP address or email given with a
//!   length of 0 is a C string.
//! - Looking a name up sorts the added parameters by name, which changes the order
//!   `X509_VERIFY_PARAM_get0` sees them in.
//!
//! The type is opaque in OpenSSL's headers, so its layout is ours (OpenSSL's, in fact).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_ulong};
use core::ptr;
use std::sync::Mutex;

use libc::time_t;
use rustyssl_abi::{
    ASN1_OBJECT, ERR_LIB_X509, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    X509_PURPOSE_CODE_SIGN, X509_PURPOSE_SMIME_SIGN, X509_PURPOSE_SSL_CLIENT,
    X509_PURPOSE_SSL_SERVER, X509_TRUST_DEFAULT, X509_TRUST_EMAIL, X509_TRUST_OBJECT_SIGN,
    X509_TRUST_SSL_CLIENT, X509_TRUST_SSL_SERVER, X509_V_FLAG_POLICY_CHECK,
    X509_V_FLAG_POLICY_MASK, X509_V_FLAG_TRUSTED_FIRST, X509_V_FLAG_USE_CHECK_TIME,
    X509_VERIFY_PARAM, X509_VP_FLAG_DEFAULT, X509_VP_FLAG_LOCKED, X509_VP_FLAG_ONCE,
    X509_VP_FLAG_OVERWRITE, X509_VP_FLAG_RESET_FLAGS, stack_st_ASN1_OBJECT,
    stack_st_OPENSSL_STRING,
};

use super::purpose::X509_PURPOSE_set;
use super::trust::X509_TRUST_set;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_dup};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};

/// `struct X509_VERIFY_PARAM_st` (`x509_local.h`).
#[repr(C)]
pub(crate) struct Param {
    pub(crate) name: *mut c_char,
    pub(crate) check_time: time_t,
    pub(crate) inh_flags: u32,
    pub(crate) flags: c_ulong,
    pub(crate) purpose: c_int,
    pub(crate) trust: c_int,
    pub(crate) depth: c_int,
    pub(crate) auth_level: c_int,
    pub(crate) policies: *mut stack_st_ASN1_OBJECT,
    pub(crate) hosts: *mut stack_st_OPENSSL_STRING,
    pub(crate) hostflags: c_uint,
    pub(crate) peername: *mut c_char,
    pub(crate) email: *mut c_char,
    pub(crate) emaillen: usize,
    pub(crate) ip: *mut c_uchar,
    pub(crate) iplen: usize,
}

/// A flag of `x509_vfy.h` (all positive) as the `unsigned long` the parameters hold.
const fn flag(v: c_int) -> c_ulong {
    let u: u32 = v.cast_unsigned();
    u as c_ulong
}

/// An inheritance flag of `x509_vfy.h` (all positive).
const fn inh(v: c_int) -> u32 {
    v.cast_unsigned()
}

/// A parameter of the built-in table: a name, flags, purpose, trust, and depth.
const fn builtin(
    name: &'static CStr,
    flags: c_ulong,
    purpose: c_int,
    trust: c_int,
    depth: c_int,
) -> Param {
    Param {
        name: name.as_ptr().cast_mut(),
        check_time: 0,
        inh_flags: 0,
        flags,
        purpose,
        trust,
        depth,
        auth_level: -1,
        policies: ptr::null_mut(),
        hosts: ptr::null_mut(),
        hostflags: 0,
        peername: ptr::null_mut(),
        email: ptr::null_mut(),
        emaillen: 0,
        ip: ptr::null_mut(),
        iplen: 0,
    }
}

/// The built-in parameters, sorted by name (`default_table`).
struct Builtins([Param; 6]);
// SAFETY: immutable, with pointers only to static names.
unsafe impl Sync for Builtins {}

static BUILTINS: Builtins = Builtins([
    builtin(
        c"code_sign",
        0,
        X509_PURPOSE_CODE_SIGN,
        X509_TRUST_OBJECT_SIGN,
        -1,
    ),
    builtin(c"default", flag(X509_V_FLAG_TRUSTED_FIRST), 0, 0, 100),
    builtin(c"pkcs7", 0, X509_PURPOSE_SMIME_SIGN, X509_TRUST_EMAIL, -1),
    builtin(
        c"smime_sign",
        0,
        X509_PURPOSE_SMIME_SIGN,
        X509_TRUST_EMAIL,
        -1,
    ),
    builtin(
        c"ssl_client",
        0,
        X509_PURPOSE_SSL_CLIENT,
        X509_TRUST_SSL_CLIENT,
        -1,
    ),
    builtin(
        c"ssl_server",
        0,
        X509_PURPOSE_SSL_SERVER,
        X509_TRUST_SSL_SERVER,
        -1,
    ),
]);

/// An added parameter, which the table owns.
struct Added(*mut Param);
// SAFETY: the table owns the parameters; OpenSSL's table is no more guarded than this.
unsafe impl Send for Added {}

/// The added parameters (`param_table`), in OpenSSL's order; `None` before the first.
static TABLE: Mutex<Option<Vec<Added>>> = Mutex::new(None);

fn table() -> std::sync::MutexGuard<'static, Option<Vec<Added>>> {
    TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A parameter's name, for ordering (`strcmp`; no name sorts first).
///
/// # Safety
/// `p` is a live parameter.
unsafe fn name_of<'a>(p: *const Param) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { (*p).name };
    // SAFETY: a parameter's name is NULL or a C string.
    (!n.is_null()).then(|| unsafe { CStr::from_ptr(n) }.to_bytes())
}

/// The caller's parameter, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a live parameter.
unsafe fn vpm<'a>(p: *const X509_VERIFY_PARAM) -> Option<&'a Param> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Param>().as_ref() }
}

/// As [`param`], to change.
///
/// # Safety
/// `p` is NULL or a live parameter no one else is using.
unsafe fn vpm_mut<'a>(p: *mut X509_VERIFY_PARAM) -> Option<&'a mut Param> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Param>().as_mut() }
}

/// `str_free`, as a stack's free function.
unsafe extern "C" fn str_free(s: *mut core::ffi::c_void) {
    // SAFETY: a string of the stack, which the stack owned.
    unsafe { mem::release(s) };
}

/// `ASN1_OBJECT_free`, as a stack's free function.
unsafe extern "C" fn obj_free(o: *mut core::ffi::c_void) {
    // SAFETY: an object of the stack, which the stack owned.
    unsafe { ASN1_OBJECT_free(o.cast()) };
}

/// A copy of `octets` and a NUL, in C memory, or NULL.
fn c_copy(octets: &[u8]) -> *mut c_char {
    let Some(n) = octets.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let p = mem::alloc(n).cast::<u8>();
    if !p.is_null() {
        // SAFETY: the new block holds `n` octets.
        let block = unsafe { core::slice::from_raw_parts_mut(p, n) };
        if let Some((last, body)) = block.split_last_mut() {
            body.copy_from_slice(octets);
            *last = 0;
        }
    }
    p.cast()
}

/// `int_x509_param_set_hosts`: sets (`add` false) or adds a host name of `namelen` octets (a C
/// string for 0, or NULL to clear): 1, or 0 for a name holding a NUL (but at its end).
///
/// # Safety
/// `name` is NULL, a C string for a `namelen` of 0, or holds `namelen` octets.
unsafe fn set_hosts(vpm: &mut Param, add: bool, name: *const c_char, namelen: usize) -> c_int {
    let text: &[u8] = if name.is_null() {
        &[]
    } else if namelen == 0 {
        // SAFETY: the caller's guarantee.
        unsafe { CStr::from_ptr(name) }.to_bytes()
    } else {
        // SAFETY: as above.
        let t = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), namelen) };
        // A NUL may end the name, but not be in it.
        let body = if namelen > 1 { namelen - 1 } else { namelen };
        if t.get(..body).unwrap_or(t).contains(&0) {
            return 0;
        }
        t
    };
    let text = match text.split_last() {
        Some((0, rest)) => rest,
        _ => text,
    };
    if !add {
        // SAFETY: its own stack of C strings, or NULL.
        unsafe { OPENSSL_sk_pop_free(vpm.hosts.cast(), Some(str_free)) };
        vpm.hosts = ptr::null_mut();
    }
    if text.is_empty() {
        return 1;
    }
    let copy = c_copy(text);
    if copy.is_null() {
        return 0;
    }
    if vpm.hosts.is_null() {
        // SAFETY: no preconditions.
        vpm.hosts = unsafe { OPENSSL_sk_new_null() }.cast();
        if vpm.hosts.is_null() {
            // SAFETY: made above.
            unsafe { mem::release(copy.cast()) };
            return 0;
        }
    }
    // SAFETY: its stack; the copy, which it takes.
    if unsafe { OPENSSL_sk_push(vpm.hosts.cast(), copy.cast()) } == 0 {
        // SAFETY: as above.
        unsafe { mem::release(copy.cast()) };
        // SAFETY: its stack.
        if unsafe { OPENSSL_sk_num(vpm.hosts.cast()) } == 0 {
            // SAFETY: as above, empty.
            unsafe { OPENSSL_sk_free(vpm.hosts.cast()) };
            vpm.hosts = ptr::null_mut();
        }
        return 0;
    }
    1
}

ffi_export! {
    /// A new parameter: no flags, purpose, or trust (`X509_TRUST_DEFAULT`), and no depth or
    /// security level (-1); or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_new() -> *mut X509_VERIFY_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let p = mem::alloc_zeroed(size_of::<Param>()).cast::<Param>();
        // SAFETY: new and zeroed, or NULL; a zeroed `Param` is valid.
        if let Some(param) = unsafe { p.as_mut() } {
            param.trust = X509_TRUST_DEFAULT;
            param.depth = -1;
            param.auth_level = -1;
        }
        p.cast()
    }
}

ffi_export! {
    /// Frees the parameter and what it holds (nothing for NULL).
    ///
    /// # Safety
    /// `param` is NULL or a parameter made by `X509_VERIFY_PARAM_new` and not otherwise used.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_free(param: *mut X509_VERIFY_PARAM)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return };
        // SAFETY: its own stack of objects, or NULL.
        unsafe { OPENSSL_sk_pop_free(p.policies.cast(), Some(obj_free)) };
        // SAFETY: its own stack of C strings, or NULL.
        unsafe { OPENSSL_sk_pop_free(p.hosts.cast(), Some(str_free)) };
        for s in [p.name.cast::<core::ffi::c_void>(), p.peername.cast(), p.email.cast(), p.ip.cast()] {
            // SAFETY: its own C memory, or NULL.
            unsafe { mem::release(s) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(param.cast()) };
    }
}

/// `int_x509_param_set1`: a copy of `src` (`srclen` octets, a C string for 0) and its length
/// into `*pdest` and `*pdestlen`, or NULL and 0 for NULL: 1, or 0.
///
/// # Safety
/// `src` is NULL, a C string for a `srclen` of 0, or holds `srclen` octets; `*pdest` is NULL
/// or C memory the parameter owns.
unsafe fn set1(
    pdest: &mut *mut c_char,
    pdestlen: &mut usize,
    src: *const c_char,
    srclen: usize,
) -> c_int {
    let (tmp, len) = if src.is_null() {
        (ptr::null_mut(), 0)
    } else {
        let octets: &[u8] = if srclen == 0 {
            // SAFETY: the caller's guarantee.
            unsafe { CStr::from_ptr(src) }.to_bytes()
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts(src.cast(), srclen) }
        };
        let t = c_copy(octets);
        if t.is_null() {
            return 0;
        }
        (t, octets.len())
    };
    // SAFETY: the caller's guarantee.
    unsafe { mem::release((*pdest).cast()) };
    *pdest = tmp;
    *pdestlen = len;
    1
}

/// `x509_verify_param_copy`'s test: whether `src`'s field (`set`, not the default) goes to
/// `dest` (whose is `dest_default`).
const fn copies(to_overwrite: bool, to_default: bool, set: bool, dest_default: bool) -> bool {
    to_overwrite || (set && (to_default || dest_default))
}

ffi_export! {
    /// Copies `src`'s settings into `dest` as their and the inheritance flags say (see
    /// `X509_VERIFY_PARAM_inherit(3)`): 1, or 0.
    ///
    /// # Safety
    /// `dest` is NULL or a live parameter; `src` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_inherit(dest: *mut X509_VERIFY_PARAM, src: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { vpm(src) }) else { return 1 };
        // Inheriting from itself does nothing (OpenSSL may free the lists it then copies).
        if ptr::eq(dest.cast_const(), src) {
            return 1;
        }
        // SAFETY: as above, and not `src`.
        let Some(d) = (unsafe { vpm_mut(dest) }) else { return 0 };
        let inh_flags = d.inh_flags | s.inh_flags;
        if inh_flags & inh(X509_VP_FLAG_ONCE) != 0 {
            d.inh_flags = 0;
        }
        if inh_flags & inh(X509_VP_FLAG_LOCKED) != 0 {
            return 1;
        }
        let to_default = inh_flags & inh(X509_VP_FLAG_DEFAULT) != 0;
        let ow = inh_flags & inh(X509_VP_FLAG_OVERWRITE) != 0;
        let int = |sv: c_int, dv: &mut c_int, def: c_int| {
            if copies(ow, to_default, sv != def, *dv == def) {
                *dv = sv;
            }
        };
        int(s.purpose, &mut d.purpose, 0);
        int(s.trust, &mut d.trust, X509_TRUST_DEFAULT);
        int(s.depth, &mut d.depth, -1);
        int(s.auth_level, &mut d.auth_level, -1);
        if ow || d.flags & flag(X509_V_FLAG_USE_CHECK_TIME) == 0 {
            d.check_time = s.check_time;
            d.flags &= !flag(X509_V_FLAG_USE_CHECK_TIME);
        }
        if inh_flags & inh(X509_VP_FLAG_RESET_FLAGS) != 0 {
            d.flags = 0;
        }
        d.flags |= s.flags;
        if copies(ow, to_default, !s.policies.is_null(), d.policies.is_null()) {
            // SAFETY: the parameters; its policies.
            if unsafe { X509_VERIFY_PARAM_set1_policies(dest, s.policies) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above, after the call.
        let Some(d) = (unsafe { vpm_mut(dest) }) else { return 0 };
        if copies(ow, to_default, s.hostflags != 0, d.hostflags == 0) {
            d.hostflags = s.hostflags;
        }
        if copies(ow, to_default, !s.hosts.is_null(), d.hosts.is_null()) {
            // SAFETY: its own stack of C strings, or NULL.
            unsafe { OPENSSL_sk_pop_free(d.hosts.cast(), Some(str_free)) };
            d.hosts = ptr::null_mut();
            if !s.hosts.is_null() {
                // SAFETY: `src`'s stack of C strings.
                d.hosts = unsafe { deep_copy(s.hosts) };
                if d.hosts.is_null() {
                    return 0;
                }
            }
        }
        if copies(ow, to_default, !s.email.is_null(), d.email.is_null()) {
            // SAFETY: its own email; `src`'s, of its length.
            if unsafe { set1(&mut d.email, &mut d.emaillen, s.email, s.emaillen) } == 0 {
                return 0;
            }
        }
        if copies(ow, to_default, !s.ip.is_null(), d.ip.is_null()) {
            // SAFETY: the parameter; `src`'s address, of its length.
            if unsafe { X509_VERIFY_PARAM_set1_ip(dest, s.ip, s.iplen) } == 0 {
                return 0;
            }
        }
        1
    }
}

/// A copy of a stack of C strings, or NULL.
///
/// # Safety
/// `sk` is a live stack of C strings.
unsafe fn deep_copy(sk: *mut stack_st_OPENSSL_STRING) -> *mut stack_st_OPENSSL_STRING {
    // SAFETY: no preconditions.
    let out = unsafe { OPENSSL_sk_new_null() };
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack; a C string of it.
        let s = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast::<c_char>();
        // SAFETY: as above.
        let copy = c_copy(unsafe { CStr::from_ptr(s) }.to_bytes());
        // SAFETY: the new stack; the copy, which it takes.
        if copy.is_null() || unsafe { OPENSSL_sk_push(out, copy.cast()) } == 0 {
            // SAFETY: made above, or NULL.
            unsafe { mem::release(copy.cast()) };
            // SAFETY: the new stack and its copies.
            unsafe { OPENSSL_sk_pop_free(out, Some(str_free)) };
            return ptr::null_mut();
        }
    }
    out.cast()
}

ffi_export! {
    /// Copies `from`'s settings that are set into `to`, as `X509_VERIFY_PARAM_inherit` with
    /// `X509_VP_FLAG_DEFAULT`: 1, or 0 (`ERR_R_PASSED_NULL_PARAMETER` for no `to`).
    ///
    /// # Safety
    /// `to` and `from` are NULL or live parameters.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1(to: *mut X509_VERIFY_PARAM, from: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { vpm_mut(to) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_VERIFY_PARAM_set1");
            return 0;
        };
        let save_flags = t.inh_flags;
        t.inh_flags |= inh(X509_VP_FLAG_DEFAULT);
        // SAFETY: the caller's guarantee.
        let ret = unsafe { X509_VERIFY_PARAM_inherit(to, from) };
        // SAFETY: as above.
        if let Some(t) = unsafe { vpm_mut(to) } {
            t.inh_flags = save_flags;
        }
        ret
    }
}

ffi_export! {
    /// Sets the parameter's name (a copy): 1, or 0 (for NULL too, which clears it).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `name` is NULL or a C string.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_name(param: *mut X509_VERIFY_PARAM, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: its own name, or NULL.
        unsafe { mem::release(p.name.cast()) };
        p.name = if name.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the caller's C string.
            c_copy(unsafe { CStr::from_ptr(name) }.to_bytes())
        };
        c_int::from(!p.name.is_null())
    }
}

ffi_export! {
    /// Adds the flags (and `X509_V_FLAG_POLICY_CHECK` for any policy flag): 1, or 0 for no
    /// parameter.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_flags(param: *mut X509_VERIFY_PARAM, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        p.flags |= flags;
        if flags & flag(X509_V_FLAG_POLICY_MASK) != 0 {
            p.flags |= flag(X509_V_FLAG_POLICY_CHECK);
        }
        1
    }
}

ffi_export! {
    /// Clears the flags: 1, or 0 for no parameter.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_clear_flags(param: *mut X509_VERIFY_PARAM, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        p.flags &= !flags;
        1
    }
}

ffi_export! {
    /// The flags (0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_flags(param: *const X509_VERIFY_PARAM) -> c_ulong
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.flags)
    }
}

ffi_export! {
    /// The inheritance flags (0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_inh_flags(param: *const X509_VERIFY_PARAM) -> u32
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.inh_flags)
    }
}

ffi_export! {
    /// Sets the inheritance flags: 1, or 0 for no parameter.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_inh_flags(param: *mut X509_VERIFY_PARAM, flags: u32) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        p.inh_flags = flags;
        1
    }
}

ffi_export! {
    /// Sets the purpose (`X509_PURPOSE_set`): 1, or 0 for an unknown one.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_purpose(param: *mut X509_VERIFY_PARAM, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: its purpose.
        unsafe { X509_PURPOSE_set(&raw mut p.purpose, purpose) }
    }
}

ffi_export! {
    /// The purpose (0 for none or no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_purpose(param: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.purpose)
    }
}

ffi_export! {
    /// Sets the trust (`X509_TRUST_set`): 1, or 0 for an unknown one.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_trust(param: *mut X509_VERIFY_PARAM, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: its trust.
        unsafe { X509_TRUST_set(&raw mut p.trust, trust) }
    }
}

ffi_export! {
    /// Sets the depth (-1 for none).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_depth(param: *mut X509_VERIFY_PARAM, depth: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { vpm_mut(param) } {
            p.depth = depth;
        }
    }
}

ffi_export! {
    /// Sets the security level (-1 for none).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_auth_level(param: *mut X509_VERIFY_PARAM, auth_level: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { vpm_mut(param) } {
            p.auth_level = auth_level;
        }
    }
}

ffi_export! {
    /// The time to verify at (0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_time(param: *const X509_VERIFY_PARAM) -> time_t
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.check_time)
    }
}

ffi_export! {
    /// Sets the time to verify at, and `X509_V_FLAG_USE_CHECK_TIME`.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_time(param: *mut X509_VERIFY_PARAM, t: time_t)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { vpm_mut(param) } {
            p.check_time = t;
            p.flags |= flag(X509_V_FLAG_USE_CHECK_TIME);
        }
    }
}

ffi_export! {
    /// Adds the policy, which the parameter takes on success: 1, or 0.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `policy` is NULL or a live object.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_add0_policy(param: *mut X509_VERIFY_PARAM, policy: *mut ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        if p.policies.is_null() {
            // SAFETY: no preconditions.
            p.policies = unsafe { OPENSSL_sk_new_null() }.cast();
            if p.policies.is_null() {
                return 0;
            }
        }
        // SAFETY: its stack; the caller's object.
        c_int::from(unsafe { OPENSSL_sk_push(p.policies.cast(), policy.cast()) } > 0)
    }
}

ffi_export! {
    /// Sets the policies to copies of `policies` (none for NULL), adding
    /// `X509_V_FLAG_POLICY_CHECK` for a list: 1, or 0 (`ERR_R_PASSED_NULL_PARAMETER` for no
    /// parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `policies` is NULL or a live stack of objects.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_policies(param: *mut X509_VERIFY_PARAM, policies: *mut stack_st_ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_VERIFY_PARAM_set1_policies");
            return 0;
        };
        if ptr::eq(p.policies, policies) {
            // Copying its own list: copy it before freeing it (OpenSSL reads it after).
            // SAFETY: its own stack.
            let copy = unsafe { copy_objects(policies) };
            if copy.is_null() {
                return 0;
            }
            // SAFETY: its own stack of objects.
            unsafe { OPENSSL_sk_pop_free(p.policies.cast(), Some(obj_free)) };
            p.policies = copy;
            p.flags |= flag(X509_V_FLAG_POLICY_CHECK);
            return 1;
        }
        // SAFETY: its own stack of objects, or NULL.
        unsafe { OPENSSL_sk_pop_free(p.policies.cast(), Some(obj_free)) };
        p.policies = ptr::null_mut();
        if policies.is_null() {
            return 1;
        }
        // SAFETY: the caller's stack.
        p.policies = unsafe { copy_objects(policies) };
        if p.policies.is_null() {
            return 0;
        }
        p.flags |= flag(X509_V_FLAG_POLICY_CHECK);
        1
    }
}

/// Copies of a stack's objects (`OBJ_dup`) in a new stack, or NULL.
///
/// # Safety
/// `sk` is a live stack of objects.
unsafe fn copy_objects(sk: *mut stack_st_ASN1_OBJECT) -> *mut stack_st_ASN1_OBJECT {
    // SAFETY: no preconditions.
    let out = unsafe { OPENSSL_sk_new_null() };
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack.
        let oid = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: an object of the stack.
        let doid = unsafe { OBJ_dup(oid.cast()) };
        // SAFETY: the new stack; the copy, which it takes.
        if doid.is_null() || unsafe { OPENSSL_sk_push(out, doid.cast()) } == 0 {
            // SAFETY: made above, or NULL.
            unsafe { ASN1_OBJECT_free(doid) };
            // SAFETY: the new stack and its copies.
            unsafe { OPENSSL_sk_pop_free(out, Some(obj_free)) };
            return ptr::null_mut();
        }
    }
    out.cast()
}

ffi_export! {
    /// The host name at `idx`, or NULL.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_host(param: *mut X509_VERIFY_PARAM, idx: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm(param) }) else { return ptr::null_mut() };
        // SAFETY: its stack of C strings, or NULL.
        unsafe { OPENSSL_sk_value(p.hosts.cast(), idx) }.cast()
    }
}

ffi_export! {
    /// Sets the host name, the only one (none for NULL or ""): 1, or 0.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `name` is NULL, a C string for a `namelen` of 0,
    /// or holds `namelen` octets.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_host(param: *mut X509_VERIFY_PARAM, name: *const c_char, namelen: usize) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_hosts(p, false, name, namelen) }
    }
}

ffi_export! {
    /// Adds a host name (none for NULL or ""): 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_VERIFY_PARAM_set1_host`].
    pub unsafe extern "C" fn X509_VERIFY_PARAM_add1_host(param: *mut X509_VERIFY_PARAM, name: *const c_char, namelen: usize) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_hosts(p, true, name, namelen) }
    }
}

ffi_export! {
    /// Sets the host-checking flags (`X509_CHECK_FLAG_*`).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set_hostflags(param: *mut X509_VERIFY_PARAM, flags: c_uint)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { vpm_mut(param) } {
            p.hostflags = flags;
        }
    }
}

ffi_export! {
    /// The host-checking flags (0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_hostflags(param: *const X509_VERIFY_PARAM) -> c_uint
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.hostflags)
    }
}

ffi_export! {
    /// The name the peer's certificate matched, or NULL.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_peername(param: *const X509_VERIFY_PARAM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(ptr::null_mut(), |p| p.peername)
    }
}

ffi_export! {
    /// Moves `from`'s peer name (or none, for NULL) to `to`.
    ///
    /// # Safety
    /// `to` is NULL or a live parameter; `from` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_move_peername(to: *mut X509_VERIFY_PARAM, from: *mut X509_VERIFY_PARAM)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let peername = unsafe { vpm(from) }.map_or(ptr::null_mut(), |f| f.peername);
        // SAFETY: as above.
        if let Some(t) = unsafe { vpm_mut(to) }
            && t.peername != peername
        {
            // SAFETY: its own peer name, or NULL.
            unsafe { mem::release(t.peername.cast()) };
            t.peername = peername;
        }
        // SAFETY: as above.
        if let Some(f) = unsafe { vpm_mut(from) } {
            f.peername = ptr::null_mut();
        }
    }
}

ffi_export! {
    /// The email address, or NULL.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_email(param: *mut X509_VERIFY_PARAM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(ptr::null_mut(), |p| p.email)
    }
}

ffi_export! {
    /// Sets the email address (`emaillen` octets, a C string for 0; none for NULL): 1, or 0.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `email` is NULL, a C string for an `emaillen` of 0,
    /// or holds `emaillen` octets.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_email(param: *mut X509_VERIFY_PARAM, email: *const c_char, emaillen: usize) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        // SAFETY: its own email; as above.
        unsafe { set1(&mut p.email, &mut p.emaillen, email, emaillen) }
    }
}

ffi_export! {
    /// Sets the IP address (4 or 16 octets; for 0, a C string's; none for NULL): 1, or 0
    /// (`ERR_R_PASSED_INVALID_ARGUMENT` for another length).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `ip` is NULL, a C string for an `iplen` of 0, or
    /// holds `iplen` octets.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip(param: *mut X509_VERIFY_PARAM, ip: *const c_uchar, iplen: usize) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if iplen != 0 && iplen != 4 && iplen != 16 {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_INVALID_ARGUMENT, "X509_VERIFY_PARAM_set1_ip");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { vpm_mut(param) }) else { return 0 };
        let mut ipp = p.ip.cast::<c_char>();
        // SAFETY: its own address; as above.
        let ret = unsafe { set1(&mut ipp, &mut p.iplen, ip.cast(), iplen) };
        p.ip = ipp.cast();
        ret
    }
}

ffi_export! {
    /// Sets the IP address from text (`ossl_a2i_ipadd`): 1, or 0 for none.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter; `ipasc` is NULL or a C string.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip_asc(param: *mut X509_VERIFY_PARAM, ipasc: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if ipasc.is_null() {
            return 0;
        }
        // SAFETY: the caller's C string.
        let Some(ip) = rustyssl_pki::ip::parse(unsafe { CStr::from_ptr(ipasc) }.to_bytes()) else { return 0 };
        // SAFETY: the caller's guarantee; the address's octets.
        unsafe { X509_VERIFY_PARAM_set1_ip(param, ip.as_ptr(), ip.len()) }
    }
}

ffi_export! {
    /// The IP address as text (`ossl_ipaddr_to_asc`), which the caller frees, or NULL
    /// (`ERR_R_PASSED_NULL_PARAMETER` for none).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get1_ip_asc(param: *mut X509_VERIFY_PARAM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let p = unsafe { vpm(param) }.filter(|p| !p.ip.is_null());
        let Some(p) = p else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "int_X509_VERIFY_PARAM_get0_ip");
            return ptr::null_mut();
        };
        // SAFETY: its address, of its length.
        let ip = unsafe { core::slice::from_raw_parts(p.ip, p.iplen) };
        c_copy(rustyssl_pki::ip::to_text(ip).as_bytes())
    }
}

ffi_export! {
    /// The depth (-1 for none, 0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_depth(param: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.depth)
    }
}

ffi_export! {
    /// The security level (-1 for none, 0 for no parameter).
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_auth_level(param: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(0, |p| p.auth_level)
    }
}

ffi_export! {
    /// The parameter's name, or NULL.
    ///
    /// # Safety
    /// `param` is NULL or a live parameter.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_name(param: *const X509_VERIFY_PARAM) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { vpm(param) }.map_or(ptr::null(), |p| p.name.cast_const())
    }
}

/// Sorts the added parameters by name, as `sk_X509_VERIFY_PARAM_sort` does.
fn sort(t: &mut [Added]) {
    // SAFETY: the table's parameters are live.
    t.sort_by(|a, b| unsafe { name_of(a.0) }.cmp(&unsafe { name_of(b.0) }));
}

/// The index of the added parameter named `name` in the sorted table, if there's one.
fn find(t: &[Added], name: Option<&[u8]>) -> Option<usize> {
    // SAFETY: the table's parameters are live.
    t.binary_search_by(|a| unsafe { name_of(a.0) }.cmp(&name))
        .ok()
}

ffi_export! {
    /// Adds the parameter to the table, which takes it, replacing (and freeing) one of its
    /// name: 1, or 0.
    ///
    /// # Safety
    /// `param` is a live parameter made by `X509_VERIFY_PARAM_new`, not otherwise used after.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_add0_table(param: *mut X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if param.is_null() {
            return 0;
        }
        let p = param.cast::<Param>();
        let mut guard = table();
        match guard.as_mut() {
            None => {
                *guard = Some(vec![Added(p)]);
            }
            Some(t) => {
                sort(t);
                // SAFETY: the caller's parameter.
                if let Some(i) = find(t, unsafe { name_of(p) }) {
                    let old = t.remove(i);
                    // Adding the same parameter again keeps it (OpenSSL frees it, then adds it).
                    if !ptr::eq(old.0, p) {
                        // SAFETY: the table owned it.
                        unsafe { X509_VERIFY_PARAM_free(old.0.cast()) };
                    }
                }
                t.push(Added(p));
            }
        }
        1
    }
}

ffi_export! {
    /// The number of named parameters: the built-in ones and those added.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get_count() -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let added = table().as_ref().map_or(0, Vec::len);
        c_int::try_from(BUILTINS.0.len().saturating_add(added)).unwrap_or(c_int::MAX)
    }
}

ffi_export! {
    /// The named parameter at `id`: the built-in ones, then those added; NULL past them
    /// (`ERR_R_PASSED_INVALID_ARGUMENT` for a negative one).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_get0(id: c_int) -> *const X509_VERIFY_PARAM
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        let Ok(i) = usize::try_from(id) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_INVALID_ARGUMENT, "X509_VERIFY_PARAM_get0");
            return ptr::null();
        };
        if let Some(p) = BUILTINS.0.get(i) {
            return ptr::from_ref(p).cast();
        }
        let added = table();
        let p = i.checked_sub(BUILTINS.0.len()).and_then(|j| added.as_ref()?.get(j));
        p.map_or(ptr::null(), |a| a.0.cast_const().cast())
    }
}

ffi_export! {
    /// The named parameter `name`: an added one first (sorting them), then a built-in one; or
    /// NULL.
    ///
    /// # Safety
    /// `name` is NULL or a C string.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_lookup(name: *const c_char) -> *const X509_VERIFY_PARAM
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let key = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_bytes());
        {
            let mut guard = table();
            if let Some(t) = guard.as_mut() {
                sort(t);
                if let Some(a) = find(t, key).and_then(|i| t.get(i)) {
                    return a.0.cast_const().cast();
                }
            }
        }
        let builtin = BUILTINS
            .0
            // SAFETY: a built-in parameter, with a static name.
            .binary_search_by(|p| unsafe { name_of(p) }.cmp(&key))
            .ok()
            .and_then(|i| BUILTINS.0.get(i));
        builtin.map_or(ptr::null(), |p| ptr::from_ref(p).cast())
    }
}

ffi_export! {
    /// Frees the added parameters.
    ///
    /// # Safety
    /// No parameter of the table is in use.
    pub unsafe extern "C" fn X509_VERIFY_PARAM_table_cleanup()
    where failure = (), library = ERR_LIB_X509
    {
        let added = table().take();
        for a in added.into_iter().flatten() {
            // SAFETY: the table owned it.
            unsafe { X509_VERIFY_PARAM_free(a.0.cast()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_parameters_are_safe() {
        let p: *mut X509_VERIFY_PARAM = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_VERIFY_PARAM_get_flags(p) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_set_flags(p, 1) }, 0);
        // SAFETY: as above.
        let r = unsafe { X509_VERIFY_PARAM_set1_host(p, c"a".as_ptr(), 0) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_VERIFY_PARAM_get0_name(p) }.is_null());
        // SAFETY: as above.
        unsafe { X509_VERIFY_PARAM_set_depth(p, 3) };
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_get_depth(p) }, 0);
        // SAFETY: as above; a built-in parameter.
        let src = unsafe { X509_VERIFY_PARAM_get0(0) };
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_inherit(p, src) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_add0_table(p) }, 0);
    }

    #[test]
    fn adding_a_parameter_twice_keeps_it() {
        // SAFETY: no preconditions.
        let p = unsafe { X509_VERIFY_PARAM_new() };
        // SAFETY: the new parameter; a static name.
        let r = unsafe { X509_VERIFY_PARAM_set1_name(p, c"twice".as_ptr()) };
        assert_eq!(r, 1);
        // SAFETY: the parameter, which the table takes.
        assert_eq!(unsafe { X509_VERIFY_PARAM_add0_table(p) }, 1);
        // SAFETY: as above, again.
        assert_eq!(unsafe { X509_VERIFY_PARAM_add0_table(p) }, 1);
        // SAFETY: a static name.
        let found = unsafe { X509_VERIFY_PARAM_lookup(c"twice".as_ptr()) };
        assert!(ptr::eq(found, p));
        // SAFETY: the table's parameter, still live.
        assert_eq!(unsafe { X509_VERIFY_PARAM_get_depth(found) }, -1);
        // SAFETY: no parameter of the table is in use.
        unsafe { X509_VERIFY_PARAM_table_cleanup() };
    }

    #[test]
    fn inheriting_from_itself_does_nothing() {
        // SAFETY: no preconditions.
        let p = unsafe { X509_VERIFY_PARAM_new() };
        // SAFETY: the new parameter; a static name.
        let r = unsafe { X509_VERIFY_PARAM_set1_host(p, c"a.example".as_ptr(), 0) };
        assert_eq!(r, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_set_flags(p, 4) }, 1);
        let inh = inh(X509_VP_FLAG_DEFAULT | X509_VP_FLAG_RESET_FLAGS);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_set_inh_flags(p, inh) }, 1);
        // SAFETY: as above, from itself.
        assert_eq!(unsafe { X509_VERIFY_PARAM_inherit(p, p) }, 1);
        // SAFETY: as above.
        assert!(!unsafe { X509_VERIFY_PARAM_get0_host(p, 0) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_VERIFY_PARAM_get_flags(p) }, 4);
        // SAFETY: made above.
        unsafe { X509_VERIFY_PARAM_free(p) };
    }
}
