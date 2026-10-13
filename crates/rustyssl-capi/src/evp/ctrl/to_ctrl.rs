//! Parameters to ctrls (`evp_pkey_ctx_setget_params_to_ctrl`): `EVP_PKEY_CTX_set_params` and
//! `EVP_PKEY_CTX_get_params` with a legacy context, each parameter translated (by the same table,
//! found by its key) to a ctrl of the context's method and the ctrl's answer back.
//!
//! As in OpenSSL, quirks included (applications' methods see exactly these ctrls):
//! - Setting a parameter whose translation is a string fails without a ctrl (the reference has
//!   no room for the string), except an EC curve name; getting one passes the ctrl no pointer and
//!   gives back an empty string.
//! - Getting the HKDF mode gives the length of the mode's name; getting a KDF type gives
//!   nothing for "none" and fails.
//! - Octets set by a parameter are copied for the ctrl and kept (the reference never frees
//!   them, and a method may keep the pointer).
//!
//! Setting the HKDF mode, where the reference compares the NULL name it has with the modes'
//! names, fails instead (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_LIB_RSA, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_UNSUPPORTED, EVP_PKEY_CTX,
    EVP_R_COMMAND_NOT_SUPPORTED, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER,
    RSA_R_UNKNOWN_PADDING_TYPE,
};

use super::{
    Action, By, Fixup as X, INT, NAME_SIZE, NAME_SIZE_INT, OCTET_PTR, OCTETS, Translation, UINT,
    UTF8, algo_name, lookup,
};
use crate::err;
use crate::evp::pkey_ctx::{self, PkeyCtx};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_ptr, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_ptr, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_uint,
    OSSL_PARAM_set_utf8_string,
};

/// The fixups' two states here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pre = 7,
    Post = 8,
}

/// What `p2` is.
#[derive(Clone, Copy)]
enum P2 {
    Ptr(*mut c_void),
    /// The context's `name_buf` (its pointer taken fresh at each use).
    NameBuf,
    /// The address of the context's `bufp`, for an octet pointer to be got.
    Bufp,
}

/// `struct translation_ctx_st` for this direction. It isn't moved while the ctrl has `p2`.
struct Ctx<'a> {
    pctx: &'a PkeyCtx,
    action: Action,
    /// The caller's parameter.
    param: *mut OSSL_PARAM,
    p1: c_int,
    p2: P2,
    bufp: *mut c_void,
    name_buf: [u8; NAME_SIZE],
}

impl Ctx<'_> {
    fn p2(&mut self) -> *mut c_void {
        match self.p2 {
            P2::Ptr(p) => p,
            P2::NameBuf => self.name_buf.as_mut_ptr().cast(),
            P2::Bufp => (&raw mut self.bufp).cast(),
        }
    }

    fn p2_is_null(&self) -> bool {
        matches!(self.p2, P2::Ptr(p) if p.is_null())
    }

    /// Points `p2` at a static string, and `p1` at its length.
    fn set_static(&mut self, s: &'static CStr) {
        self.p2 = P2::Ptr(s.as_ptr().cast_mut().cast());
        self.p1 = c_int::try_from(s.to_bytes().len()).unwrap_or(0);
    }

    /// Points `p2` at `name_buf` holding `s` (truncated to fit), and `p1` at its length.
    fn set_name(&mut self, s: &[u8]) {
        self.name_buf = [0; NAME_SIZE];
        let mut n = 0;
        for (d, &b) in self.name_buf.iter_mut().zip(s.iter().take(NAME_SIZE - 1)) {
            *d = b;
            n += 1;
        }
        self.p2 = P2::NameBuf;
        self.p1 = c_int::try_from(n).unwrap_or(0);
    }

    /// The string `p2` points to (empty for NULL).
    ///
    /// # Safety
    /// `p2` is NULL or a string.
    unsafe fn p2_str(&self) -> &CStr {
        match self.p2 {
            P2::NameBuf => CStr::from_bytes_until_nul(&self.name_buf).unwrap_or(c""),
            // SAFETY: the caller's guarantee.
            P2::Ptr(p) if !p.is_null() => unsafe { CStr::from_ptr(p.cast()) },
            _ => c"",
        }
    }
}

/// `default_check` for this direction.
fn default_check(tr: Option<&Translation>) -> Option<&Translation> {
    if tr.is_none() {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "default_check");
    }
    tr
}

/// `default_fixup_args` for this direction: the parameter's value into `p1` or `p2` before the
/// ctrl (setting), the ctrl's answer into the parameter after (getting).
///
/// # Safety
/// `c.param` is the caller's live parameter; `p2` is what the data type needs.
unsafe fn default_fixup(state: State, tr: Option<&Translation>, c: &mut Ctx<'_>) -> c_int {
    const F: &str = "default_fixup_args";
    let Some(tr) = default_check(tr) else {
        return -2;
    };
    let ret = if state == State::Post { c.p1 } else { 1 };
    match (state, c.action) {
        (State::Pre, Action::Set) => match tr.data_type {
            // SAFETY: the caller's parameter; the context's value, here and below.
            INT => unsafe { OSSL_PARAM_get_int(c.param, &raw mut c.p1) },
            // SAFETY: as above (an `unsigned int` in the same place).
            UINT => unsafe { OSSL_PARAM_get_uint(c.param, (&raw mut c.p1).cast::<c_uint>()) },
            UTF8 => {
                // `p2` is where the string goes: NULL (which fails) but for the EC curve's name.
                let p2 = c.p2().cast::<*mut c_char>();
                // SAFETY: the caller's parameter; NULL or the fixup's room for a pointer.
                unsafe { OSSL_PARAM_get_utf8_string(c.param, p2, 0) }
            }
            OCTETS => {
                let mut p: *mut c_void = ptr::null_mut();
                let mut used = 0usize;
                // A copy of the octets, which the reference never frees (the method may keep
                // them).
                // SAFETY: the caller's parameter; the locals.
                let ok =
                    unsafe { OSSL_PARAM_get_octet_string(c.param, &raw mut p, 0, &raw mut used) };
                c.p2 = P2::Ptr(p);
                c.p1 = c_int::try_from(used).unwrap_or(c_int::MAX);
                ok
            }
            OCTET_PTR => {
                let mut size = 0usize;
                // The reference has no room for the pointer: NULL, which fails.
                // SAFETY: the caller's parameter.
                unsafe { OSSL_PARAM_get_octet_ptr(c.param, ptr::null_mut(), &raw mut size) }
            }
            t => {
                err::raise_with_text(
                    ERR_LIB_EVP,
                    ERR_R_UNSUPPORTED,
                    F,
                    &format!(
                        "[action:{}, state:{}] unknown OSSL_PARAM data type {t}",
                        c.action as c_int, state as c_int
                    ),
                );
                0
            }
        },
        (State::Post, Action::Get) => {
            let size = usize::try_from(c.p1).unwrap_or(0);
            match tr.data_type {
                // SAFETY: the caller's parameter, here and below.
                INT => unsafe { OSSL_PARAM_set_int(c.param, c.p1) },
                // SAFETY: as above.
                UINT => unsafe { OSSL_PARAM_set_uint(c.param, c.p1.cast_unsigned()) },
                UTF8 => {
                    let s = if c.p2_is_null() {
                        ptr::null()
                    } else {
                        c.p2().cast_const().cast()
                    };
                    // SAFETY: as above; NULL or the string `p2` points to.
                    unsafe { OSSL_PARAM_set_utf8_string(c.param, s) }
                }
                OCTETS => {
                    let p = c.p2();
                    // SAFETY: as above; the octets `p2` points to.
                    unsafe { OSSL_PARAM_set_octet_string(c.param, p, size) }
                }
                OCTET_PTR => {
                    let p = match c.p2 {
                        P2::Bufp => c.bufp,
                        _ => ptr::null_mut(),
                    };
                    // SAFETY: as above; the pointer the ctrl gave.
                    unsafe { OSSL_PARAM_set_octet_ptr(c.param, p, size) }
                }
                t => {
                    err::raise_with_text(
                        ERR_LIB_EVP,
                        ERR_R_UNSUPPORTED,
                        F,
                        &format!(
                            "[action:{}, state:{}] unsupported OSSL_PARAM data type {t}",
                            c.action as c_int, state as c_int
                        ),
                    );
                    0
                }
            }
        }
        (State::Pre, Action::Get) => {
            if tr.data_type == OCTET_PTR {
                c.p2 = P2::Bufp;
            }
            ret
        }
        _ => ret,
    }
}

/// `fix_cipher_md`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_cipher_md(state: State, tr: &Translation, c: &mut Ctx<'_>, cipher: bool) -> c_int {
    if state == State::Post && c.action == Action::Get {
        let name = if c.p2_is_null() {
            c"".as_ptr()
        } else {
            // SAFETY: what the ctrl left `p2` as: a digest (cipher), never in practice.
            unsafe { algo_name(c.p2(), cipher) }
        };
        c.p2 = P2::Ptr(name.cast_mut().cast());
        // SAFETY: NULL or a static name.
        c.p1 = c_int::try_from(unsafe { c.p2_str() }.to_bytes().len()).unwrap_or(0);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::Pre && c.action == Action::Set {
        // The name the parameter gave (never reached: setting a string fails above).
        let libctx = c.pctx.lock().libctx.0;
        // SAFETY: the string `p2` points to.
        let name = unsafe { c.p2_str() }.as_ptr();
        let found: *const c_void = if cipher {
            // SAFETY: the context's library context; a string.
            unsafe { crate::evp::legacy_cipher::get_cipherbyname_ex(libctx, name) }.cast()
        } else {
            // SAFETY: as above.
            unsafe { crate::evp::legacy_md::get_digestbyname_ex(libctx, name) }.cast()
        };
        c.p2 = P2::Ptr(found.cast_mut());
        c.p1 = 0;
    }
    ret
}

/// `fix_kdf_type`: the type's number to the ctrl (from its name), and its name back.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_kdf_type(
    state: State,
    tr: &Translation,
    c: &mut Ctx<'_>,
    map: &[(c_int, &'static CStr)],
) -> c_int {
    if state == State::Post && c.action == Action::Get {
        let Some((_, name)) = map.iter().find(|(n, _)| *n == c.p1) else {
            return -2;
        };
        c.set_static(name);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::Pre && c.action == Action::Set {
        // Never reached: setting a string fails above.
        // SAFETY: the string `p2` points to.
        let name = unsafe { c.p2_str() }.to_bytes().to_vec();
        c.p2 = P2::Ptr(ptr::null_mut());
        return match map
            .iter()
            .find(|(_, s)| s.to_bytes().eq_ignore_ascii_case(&name))
        {
            Some((n, _)) => {
                c.p1 = *n;
                1
            }
            None => {
                c.p1 = -1;
                -1
            }
        };
    }
    if state == State::Pre && c.action == Action::Get {
        c.p1 = -2;
    }
    ret
}

/// `fix_oid`.
///
/// # Safety
/// As for [`default_fixup`]; for a getter, `p2` is NULL or a live object.
unsafe fn fix_oid(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if state == State::Post && c.action == Action::Get {
        c.name_buf = [0; NAME_SIZE];
        let obj = c.p2().cast_const().cast();
        // SAFETY: the buffer and its size; the object the ctrl left (NULL in practice).
        unsafe {
            crate::objects::OBJ_obj2txt(c.name_buf.as_mut_ptr().cast(), NAME_SIZE_INT, obj, 0)
        };
        c.p2 = P2::NameBuf;
        c.p1 = 0;
    }
    // SAFETY: the caller's guarantee. (Setting, which would make an object of the name, fails
    // here: the string has no room.)
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_dh_nid`, `fix_dh_nid5114`, `fix_dh_paramgen_type`, and `fix_ec_param_enc`: only
/// settable, and a string, which fails.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_settable_string(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if c.action != Action::Set {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret > 0 && state == State::Pre && tr.fixup == X::EcParamEnc {
        // Never reached: the string has no room.
        c.p1 = -2;
        c.p2 = P2::Ptr(ptr::null_mut());
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "fix_ec_param_enc");
        return -2;
    }
    ret
}

/// `fix_ec_paramgen_curve_nid`: the curve's name to its NID.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_ec_paramgen_curve_nid(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if c.action != Action::Set {
        return 0;
    }
    if state == State::Pre {
        // The name goes in `name_buf`, through a pointer to it.
        c.name_buf = [0; NAME_SIZE];
        let mut name = c.name_buf.as_mut_ptr().cast::<c_char>();
        // SAFETY: the caller's parameter; room for the pointer, which points to the buffer of
        // its size.
        let ret = unsafe { OSSL_PARAM_get_utf8_string(c.param, &raw mut name, NAME_SIZE) };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: the NUL-terminated name.
        c.p1 = unsafe { crate::objects::OBJ_sn2nid(c.name_buf.as_ptr().cast()) };
        c.p2 = P2::Ptr(ptr::null_mut());
        return ret;
    }
    // SAFETY: the caller's guarantee.
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_ecdh_cofactor`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_ecdh_cofactor(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if state == State::Post && c.action == Action::None {
        c.action = Action::Get;
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    match (state, c.action) {
        (State::Pre, Action::Get) => c.p1 = -2,
        (State::Post, Action::Get) => c.p1 = ret,
        _ => {}
    }
    ret
}

/// `fix_rsa_padding_mode`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_rsa_padding_mode(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if state == State::Post && c.action == Action::Get {
        // SAFETY: the caller's parameter.
        let data_type = unsafe { (*c.param).data_type };
        match c_int::try_from(data_type).unwrap_or(0) {
            // The reference reads the parameter into the answer here.
            // SAFETY: the caller's parameter; the context's value.
            OSSL_PARAM_INTEGER => return unsafe { OSSL_PARAM_get_int(c.param, &raw mut c.p1) },
            OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: as above.
                return unsafe { OSSL_PARAM_get_uint(c.param, (&raw mut c.p1).cast::<c_uint>()) };
            }
            _ => {}
        }
        let Some(&(_, name)) = super::PADDINGS.iter().find(|(n, _)| *n == c.p1) else {
            err::raise_with_text(
                ERR_LIB_RSA,
                RSA_R_UNKNOWN_PADDING_TYPE,
                "fix_rsa_padding_mode",
                &format!(
                    "[action:{}, state:{}] padding number {}",
                    c.action as c_int, state as c_int, c.p1
                ),
            );
            return -2;
        };
        let Some(name) = name else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_COMMAND_NOT_SUPPORTED,
                "fix_rsa_padding_mode",
            );
            return -2;
        };
        c.set_name(name.as_bytes());
    }
    // SAFETY: the caller's guarantee. (Setting, by name, fails here: the string has no room.)
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_rsa_pss_saltlen`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_rsa_pss_saltlen(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if state == State::Post && c.action == Action::Get {
        let text = match super::SALTLENS.iter().find(|(n, _)| *n == c.p1) {
            Some((_, s)) => s.as_bytes().to_vec(),
            None => c.p1.to_string().into_bytes(),
        };
        c.set_name(&text);
    }
    // SAFETY: the caller's guarantee. (Setting, by name, fails here: the string has no room.)
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_hkdf_mode`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_hkdf_mode(state: State, tr: &Translation, c: &mut Ctx<'_>) -> c_int {
    if state == State::Post && c.action == Action::Get {
        let Some((_, name)) = super::HKDF_MODES.iter().find(|(n, _)| *n == c.p1) else {
            return 0;
        };
        c.set_static(name);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::Pre && c.action == Action::Set {
        // The reference compares the mode's name, which it hasn't got (NULL), with the names
        // (docs/DEVIATIONS.md).
        return 0;
    }
    ret
}

/// `fix_group_ecx`: no ctrl, only a check that the group is the context's key type.
///
/// # Safety
/// `c.param` is the caller's live parameter.
unsafe fn fix_group_ecx(state: State, c: &mut Ctx<'_>) -> c_int {
    match state {
        State::Pre => {
            if !c.pctx.lock().is_gen_op() {
                return 0;
            }
            c.action = Action::None;
            1
        }
        State::Post => {
            let mut value: *const c_char = ptr::null();
            // SAFETY: the caller's parameter; room for the pointer.
            let ok = unsafe { OSSL_PARAM_get_utf8_string_ptr(c.param, &raw mut value) } != 0;
            let keytype = c.pctx.lock().keytype().map(CStr::to_owned);
            let same = ok
                && keytype.is_some_and(|k| {
                    // SAFETY: the parameter's string.
                    let v = unsafe { CStr::from_ptr(value) };
                    k.to_bytes().eq_ignore_ascii_case(v.to_bytes())
                });
            if !same {
                err::raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT, "fix_group_ecx");
                c.p1 = 0;
                return 0;
            }
            c.p1 = 1;
            1
        }
    }
}

/// Runs a translation's fixup for this direction.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fixup(state: State, tr: Option<&Translation>, c: &mut Ctx<'_>) -> c_int {
    let Some(tr) = tr else {
        // SAFETY: the caller's guarantee.
        return unsafe { default_fixup(state, None, c) };
    };
    match tr.fixup {
        // SAFETY: the caller's guarantee, here and below.
        X::Default => unsafe { default_fixup(state, Some(tr), c) },
        // SAFETY: as above.
        X::Md => unsafe { fix_cipher_md(state, tr, c, false) },
        // SAFETY: as above.
        X::Cipher => unsafe { fix_cipher_md(state, tr, c, true) },
        X::DistidLen => {
            // Only a getter's length, which comes from the ctrl direction.
            // SAFETY: as above.
            let ret = unsafe { default_fixup(state, Some(tr), c) };
            ret.min(0)
        }
        // SAFETY: as above.
        X::DhKdfType => unsafe { fix_kdf_type(state, tr, c, &super::DH_KDF_TYPES) },
        // SAFETY: as above.
        X::EcKdfType => unsafe { fix_kdf_type(state, tr, c, &super::EC_KDF_TYPES) },
        // SAFETY: as above.
        X::Oid => unsafe { fix_oid(state, tr, c) },
        X::DhNid | X::DhNid5114 | X::DhParamgenType | X::EcParamEnc => {
            // SAFETY: as above.
            unsafe { fix_settable_string(state, tr, c) }
        }
        // SAFETY: as above.
        X::EcParamgenCurveNid => unsafe { fix_ec_paramgen_curve_nid(state, tr, c) },
        // SAFETY: as above.
        X::EcdhCofactor => unsafe { fix_ecdh_cofactor(state, tr, c) },
        // SAFETY: as above.
        X::RsaPadding => unsafe { fix_rsa_padding_mode(state, tr, c) },
        // SAFETY: as above.
        X::RsaPssSaltlen => unsafe { fix_rsa_pss_saltlen(state, tr, c) },
        // SAFETY: as above.
        X::HkdfMode => unsafe { fix_hkdf_mode(state, tr, c) },
        // SAFETY: as above.
        X::GroupEcx => unsafe { fix_group_ecx(state, c) },
    }
}

/// `evp_pkey_ctx_set_params_to_ctrl` (`set`) and `evp_pkey_ctx_get_params_to_ctrl`: each
/// parameter through its ctrl. 1, or 0 at the first that fails.
///
/// # Safety
/// `ctx` is NULL or a live legacy context; `params` is NULL or an array (written for getting).
pub(crate) unsafe fn params_to_ctrl(
    ctx: *mut EVP_PKEY_CTX,
    params: *mut OSSL_PARAM,
    set: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(pctx) = (unsafe { pkey_ctx::context(ctx) }) else {
        return 0;
    };
    let (keytype, op) = {
        let s = pctx.lock();
        (s.legacy_keytype(), s.operation)
    };
    let optype = if op == 0 { -1 } else { op };
    let action = if set { Action::Set } else { Action::Get };
    let mut p = params;
    // SAFETY: the caller's array, ended by a NULL key.
    while let Some(q) = unsafe { p.as_ref() } {
        if q.key.is_null() {
            break;
        }
        // SAFETY: the parameter's key.
        let key = unsafe { CStr::from_ptr(q.key) }.to_bytes();
        let tr = lookup(keytype, optype, &By::Param(key, action)).map(|(t, _)| t);
        let mut c = Ctx {
            pctx,
            action,
            param: p,
            p1: 0,
            p2: P2::Ptr(ptr::null_mut()),
            bufp: ptr::null_mut(),
            name_buf: [0; NAME_SIZE],
        };
        // SAFETY: the caller's parameter.
        let mut ret = unsafe { fixup(State::Pre, tr, &mut c) };
        if ret > 0 && c.action != Action::None {
            let cmd = tr.map_or(0, |t| t.ctrl_num);
            let p2 = c.p2();
            // SAFETY: the caller's context; what the command takes (as the fixup made it).
            ret = unsafe { super::ctrl(ctx, keytype, optype, cmd, c.p1, p2) };
        }
        // The ctrl's answer goes back (0 too: some ctrls answer 0 for success).
        if ret >= 0 {
            c.p1 = ret;
            // SAFETY: as above.
            unsafe { fixup(State::Post, tr, &mut c) };
            ret = c.p1;
        }
        if ret <= 0 {
            return 0;
        }
        p = p.wrapping_add(1);
    }
    1
}
