//! Certificates, CRLs, requests, names, stacks of them, and extensions.

use core::ffi::{c_int, c_long, c_ulong, c_void};

use crate::abi::{
    ASN1_OCTET_STRING, CONF_VALUE, OPENSSL_STACK, X509_CRL, X509_EXTENSION, X509_NAME, X509V3_CTX,
    stack_st_X509, stack_st_X509_CRL,
};
use crate::bio::Bio;
pub use crate::bn::Bn;
use crate::ffi;
pub use crate::object::Object as Obj;
pub use crate::pkcs7::Pkcs7;
use crate::pkey::{MdCtx, Pkey};
use crate::provider::LibCtx;
use crate::util::{cstring, string_at, take_string};

crate::handle!(
    /// An owned `X509`.
    Cert, X509, X509_free
);
crate::handle!(
    /// An owned `X509_CRL`.
    Crl, X509_CRL, X509_CRL_free
);
crate::handle!(
    /// An owned `X509_REQ`.
    Req, X509_REQ, X509_REQ_free
);
crate::handle!(
    /// An owned `X509_NAME`.
    Name, X509_NAME, X509_NAME_free
);

impl Cert {
    /// Takes ownership of a certificate the caller got from the library.
    pub fn from_raw(p: *mut crate::abi::X509) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `X509_get_subject_name` (borrowed for `self`'s lifetime).
    pub fn subject_name(&self) -> NameRef<'_> {
        // SAFETY: the certificate is live; the name is owned by it.
        NameRef::new(unsafe { ffi::X509_get_subject_name(self.as_ptr()) })
    }

    /// `X509_get_issuer_name`.
    pub fn issuer_name(&self) -> NameRef<'_> {
        // SAFETY: as above.
        NameRef::new(unsafe { ffi::X509_get_issuer_name(self.as_ptr()) })
    }

    /// `X509_set_version`.
    pub fn set_version(&self, version: c_long) -> bool {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_set_version(self.as_ptr(), version) == 1 }
    }

    /// `X509_check_private_key`.
    pub fn check_private_key(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::X509_check_private_key(self.as_ptr(), pkey.as_ptr()) == 1 }
    }

    /// `X509_sign_ctx`: what it returns.
    pub fn sign_ctx(&self, ctx: &MdCtx) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_sign_ctx(self.as_ptr(), ctx.as_ptr()) }
    }

    /// `X509_verify`: what it returns.
    pub fn verify(&self, pkey: &Pkey) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_verify(self.as_ptr(), pkey.as_ptr()) }
    }

    /// `X509_set0_distinguishing_id(x, ASN1_OCTET_STRING(value))`: false if the string
    /// can't be made.
    pub fn set_distinguishing_id(&self, value: &[u8]) -> bool {
        let Some(v) = octet_string(value) else {
            return false;
        };
        // SAFETY: the certificate is live and takes ownership of v.
        unsafe { ffi::X509_set0_distinguishing_id(self.as_ptr(), v) };
        true
    }

    /// The certificate's extension with the same type as `ext`, if any: its index.
    pub fn ext_index_like(&self, ext: &Extension, last: c_int) -> c_int {
        // SAFETY: both are live; the object is owned by ext.
        let obj = unsafe { ffi::X509_EXTENSION_get_object(ext.as_ptr()) };
        // SAFETY: the certificate is live; obj is valid.
        unsafe { ffi::X509_get_ext_by_OBJ(self.as_ptr(), obj, last) }
    }

    /// `X509_delete_ext` and free it.
    pub fn delete_ext(&self, idx: c_int) {
        // SAFETY: the certificate is live; what it returns is the caller's to free.
        let e = unsafe { ffi::X509_delete_ext(self.as_ptr(), idx) };
        // SAFETY: e is NULL or an extension now owned here.
        unsafe { ffi::X509_EXTENSION_free(e) };
    }

    /// `X509_add_ext(x, ext, -1)` (the certificate copies it).
    pub fn add_ext(&self, ext: &Extension) -> bool {
        // SAFETY: both are live; X509_add_ext duplicates ext.
        unsafe { ffi::X509_add_ext(self.as_ptr(), ext.as_ptr(), -1) == 1 }
    }

    /// For `adapt_keyid_ext`: the index of the certificate's extension of `ext`'s type, and
    /// whether its encoded value is at most 2 bytes long (a disabled one, "none").
    pub fn existing_ext(&self, ext: &Extension) -> Option<(c_int, bool)> {
        // SAFETY: the certificate is live; the stack is owned by it.
        let exts = unsafe { ffi::X509_get0_extensions(self.as_ptr()) };
        // SAFETY: ext is live.
        let obj = unsafe { ffi::X509_EXTENSION_get_object(ext.as_ptr()) };
        // SAFETY: exts is NULL or live; obj is valid.
        let idx = unsafe { ffi::X509v3_get_ext_by_OBJ(exts, obj, -1) };
        if idx < 0 {
            return None;
        }
        // SAFETY: idx is a valid index of exts.
        let found = unsafe { ffi::X509v3_get_ext(exts, idx) };
        // SAFETY: found is a live extension of the certificate.
        let data = unsafe { ffi::X509_EXTENSION_get_data(found) };
        // SAFETY: data is the extension's own string.
        let len = unsafe { ffi::ASN1_STRING_length(data) };
        Some((idx, len <= 2))
    }
}

/// `ASN1_OCTET_STRING` holding a copy of `value`.
fn octet_string(value: &[u8]) -> Option<*mut ASN1_OCTET_STRING> {
    // SAFETY: no arguments.
    let v = unsafe { ffi::ASN1_OCTET_STRING_new() };
    if v.is_null() {
        return None;
    }
    let len = c_int::try_from(value.len()).ok()?;
    // SAFETY: v is live; value is valid for len bytes.
    if unsafe { ffi::ASN1_OCTET_STRING_set(v, value.as_ptr(), len) } != 1 {
        // SAFETY: v is owned here.
        unsafe { ffi::ASN1_OCTET_STRING_free(v) };
        return None;
    }
    Some(v)
}

impl Crl {
    /// Takes ownership of a CRL the caller got from the library.
    pub fn from_raw(p: *mut X509_CRL) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `X509_CRL_sign_ctx`: what it returns.
    pub fn sign_ctx(&self, ctx: &MdCtx) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_CRL_sign_ctx(self.as_ptr(), ctx.as_ptr()) }
    }
}

impl Req {
    /// `d2i_X509_REQ_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_X509_REQ_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_X509_REQ(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `X509_REQ_get0_pubkey` as an owned key (`X509_REQ_get_pubkey`), if any.
    pub fn pubkey(&self) -> Option<Pkey> {
        // SAFETY: the request is live; the key returned is a new reference.
        Pkey::from_raw(unsafe { ffi::X509_REQ_get_pubkey(self.as_ptr()) })
    }

    /// `X509_REQ_sign_ctx`: what it returns.
    pub fn sign_ctx(&self, ctx: &MdCtx) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_REQ_sign_ctx(self.as_ptr(), ctx.as_ptr()) }
    }

    /// `X509_REQ_verify_ex`: what it returns.
    pub fn verify_ex(
        &self,
        pkey: Option<&Pkey>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> c_int {
        let pq = propq.map(cstring);
        if pq.as_ref().is_some_and(Option::is_none) {
            return -1;
        }
        let pqp = pq
            .as_ref()
            .and_then(|p| p.as_ref())
            .map_or(core::ptr::null(), |p| p.as_ptr());
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let key = pkey.map_or(core::ptr::null_mut(), Pkey::as_ptr);
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe { ffi::X509_REQ_verify_ex(self.as_ptr(), key, ctx, pqp) }
    }

    /// `X509_REQ_set0_distinguishing_id`.
    pub fn set_distinguishing_id(&self, value: &[u8]) -> bool {
        let Some(v) = octet_string(value) else {
            return false;
        };
        // SAFETY: the request is live and takes ownership of v.
        unsafe { ffi::X509_REQ_set0_distinguishing_id(self.as_ptr(), v) };
        true
    }

    /// `X509_REQ_get_extensions` as owned extensions.
    pub fn extensions(&self) -> Vec<Extension> {
        // SAFETY: the request is live; the stack and its members are the caller's to free.
        let sk = unsafe { ffi::X509_REQ_get_extensions(self.as_ptr()) };
        let mut out = Vec::new();
        if sk.is_null() {
            return out;
        }
        let st = sk.cast::<OPENSSL_STACK>();
        // SAFETY: st is a live stack.
        let n = unsafe { ffi::OPENSSL_sk_num(st) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each member is an X509_EXTENSION now owned here.
            let e = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<X509_EXTENSION>();
            if let Some(e) = Extension::from_ptr(e) {
                out.push(e);
            }
        }
        // SAFETY: the members are owned by `out`; only the stack itself is freed.
        unsafe { ffi::OPENSSL_sk_free(st) };
        out
    }
}

crate::handle!(
    /// An owned `X509_EXTENSION`.
    Extension, X509_EXTENSION, X509_EXTENSION_free
);

/// An `X509_NAME` borrowed from the object that owns it (NULL allowed: the C functions
/// taking one treat it as their documented NULL case).
#[derive(Clone, Copy)]
pub struct NameRef<'a>(*const X509_NAME, core::marker::PhantomData<&'a ()>);

impl NameRef<'_> {
    pub(crate) fn new(p: *const X509_NAME) -> Self {
        Self(p, core::marker::PhantomData)
    }
}

impl Name {
    /// The name, borrowed.
    pub fn as_name(&self) -> NameRef<'_> {
        NameRef::new(self.as_ptr())
    }

    /// `X509_NAME_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_NAME_new() })
    }

    /// `X509_NAME_add_entry_by_NID(n, nid, chtype, value, len, -1, set)`.
    pub fn add_entry_by_nid(&self, nid: c_int, chtype: c_int, value: &[u8], set: c_int) -> bool {
        let Ok(len) = c_int::try_from(value.len()) else {
            return false;
        };
        // SAFETY: the name is live; value is valid for len bytes.
        unsafe {
            ffi::X509_NAME_add_entry_by_NID(
                self.as_ptr(),
                nid,
                chtype,
                value.as_ptr(),
                len,
                -1,
                set,
            ) == 1
        }
    }
}

/// `X509_NAME_oneline(nm, NULL, 0)`.
pub fn name_oneline(nm: NameRef<'_>) -> Option<String> {
    if nm.0.is_null() {
        return None;
    }
    // SAFETY: nm is live (borrowed from its owner); the result is the caller's to free.
    take_string(unsafe { ffi::X509_NAME_oneline(nm.0, core::ptr::null_mut(), 0) })
}

/// `X509_NAME_print_ex(out, nm, indent, flags)`.
pub fn name_print_ex(out: &Bio, nm: NameRef<'_>, indent: c_int, flags: c_ulong) -> c_int {
    if nm.0.is_null() {
        return 0;
    }
    // SAFETY: both are live.
    unsafe { ffi::X509_NAME_print_ex(out.as_ptr(), nm.0, indent, flags) }
}

/// `OBJ_txt2nid`.
pub fn txt2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_txt2nid(c.as_ptr()) }
}

/// `OBJ_create(oid, sn, ln)`: the new NID (0 is `NID_undef`).
pub fn obj_create(oid: &str, sn: &str, ln: &str) -> c_int {
    let (Some(o), Some(s), Some(l)) = (cstring(oid), cstring(sn), cstring(ln)) else {
        return 0;
    };
    // SAFETY: valid C strings.
    unsafe { ffi::OBJ_create(o.as_ptr(), s.as_ptr(), l.as_ptr()) }
}

/// An owned `STACK_OF(X509)`, freed with `OSSL_STACK_OF_X509_free`.
pub struct CertStack(core::ptr::NonNull<stack_st_X509>);

impl CertStack {
    /// Takes ownership of a stack (and its certificates) the caller got from the library.
    pub fn from_raw(p: *mut stack_st_X509) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    /// `sk_X509_new_null()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        let p = unsafe { ffi::OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
        core::ptr::NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut stack_st_X509 {
        self.0.as_ptr()
    }

    /// `X509_add_cert(sk, cert, X509_ADD_FLAG_DEFAULT)`, which takes the certificate.
    pub fn add_cert(&self, cert: Cert) -> bool {
        let p = cert.as_ptr();
        // SAFETY: both are live; on success the stack owns the certificate.
        if unsafe { ffi::X509_add_cert(self.as_ptr(), p, crate::abi::X509_ADD_FLAG_DEFAULT) } == 1 {
            core::mem::forget(cert);
            true
        } else {
            false
        }
    }

    /// `sk_X509_num`.
    pub fn len(&self) -> usize {
        // SAFETY: the stack is live.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.as_ptr().cast()) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for CertStack {
    fn drop(&mut self) {
        // SAFETY: the stack and its certificates are owned here and freed once.
        unsafe { ffi::OSSL_STACK_OF_X509_free(self.as_ptr()) };
    }
}

unsafe extern "C" fn free_dist_point(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, a DIST_POINT.
    unsafe { ffi::DIST_POINT_free(p.cast()) };
}

unsafe extern "C" fn free_crl(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, an X509_CRL.
    unsafe { ffi::X509_CRL_free(p.cast()) };
}

/// An owned `STACK_OF(X509_CRL)`, freed with `sk_X509_CRL_pop_free(sk, X509_CRL_free)`.
pub struct CrlStack(core::ptr::NonNull<stack_st_X509_CRL>);

impl CrlStack {
    /// `sk_X509_CRL_new_null()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        let p = unsafe { ffi::OPENSSL_sk_new_null() }.cast::<stack_st_X509_CRL>();
        core::ptr::NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut stack_st_X509_CRL {
        self.0.as_ptr()
    }

    /// Gives up ownership of the stack and its CRLs.
    pub fn into_ptr(self) -> *mut stack_st_X509_CRL {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }

    /// `sk_X509_CRL_push`, which takes the CRL.
    pub fn push(&self, crl: Crl) -> bool {
        // SAFETY: both are live; on success the stack owns the CRL.
        if unsafe { ffi::OPENSSL_sk_push(self.as_ptr().cast(), crl.as_ptr().cast()) } > 0 {
            core::mem::forget(crl);
            true
        } else {
            false
        }
    }

    /// `sk_X509_CRL_num`.
    pub fn len(&self) -> usize {
        // SAFETY: the stack is live.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.as_ptr().cast()) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for CrlStack {
    fn drop(&mut self) {
        // SAFETY: the stack and its CRLs are owned here and freed once.
        unsafe { ffi::OPENSSL_sk_pop_free(self.as_ptr().cast(), Some(free_crl)) };
    }
}

/// `X509V3_parse_list(arg)`: the (name, value) pairs, or `None` if it fails.
pub fn parse_list(arg: &str) -> Option<Vec<(Option<String>, Option<String>)>> {
    let a = cstring(arg)?;
    // SAFETY: a is a valid C string; the stack and members are the caller's to free.
    let sk = unsafe { ffi::X509V3_parse_list(a.as_ptr()) };
    if sk.is_null() {
        return None;
    }
    let st = sk.cast::<OPENSSL_STACK>();
    let mut out = Vec::new();
    // SAFETY: st is live.
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; each member is a CONF_VALUE.
        let v = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<CONF_VALUE>();
        if v.is_null() {
            continue;
        }
        // SAFETY: v is a live CONF_VALUE whose fields are NULL or C strings.
        let cv = unsafe { &*v };
        let (n, val) = (cv.name, cv.value);
        let (name, value) = (string_at(n), string_at(val));
        out.push((name, value));
    }
    // SAFETY: each member is freed with X509V3_conf_free, then the stack.
    for i in 0..n.max(0) {
        // SAFETY: as above.
        let v = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<CONF_VALUE>();
        // SAFETY: v is owned here and freed once.
        unsafe { ffi::X509V3_conf_free(v) };
    }
    // SAFETY: the stack is owned here.
    unsafe { ffi::OPENSSL_sk_free(st) };
    Some(out)
}

/// An `X509V3_CTX`, at a stable address (a public struct the caller owns), using objects
/// borrowed for `'a`.
pub struct V3Ctx<'a>(Box<X509V3_CTX>, core::marker::PhantomData<&'a ()>);

impl<'a> V3Ctx<'a> {
    /// A zeroed context, as `X509V3_CTX ctx = { 0 }`... then `X509V3_set_ctx`.
    pub fn new(
        issuer: Option<&'a Cert>,
        subject: Option<&'a Cert>,
        req: Option<&'a Req>,
        crl: Option<&'a Crl>,
        flags: c_int,
    ) -> Self {
        // SAFETY: X509V3_CTX is a plain C struct of pointers and integers, for which all
        // zeroes is the valid empty value.
        let mut ctx: Box<X509V3_CTX> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: ctx is a valid context; the objects are NULL or live, and the caller keeps
        // them alive while the context is used.
        unsafe {
            ffi::X509V3_set_ctx(
                &mut *ctx,
                issuer.map_or(core::ptr::null_mut(), Cert::as_ptr),
                subject.map_or(core::ptr::null_mut(), Cert::as_ptr),
                req.map_or(core::ptr::null_mut(), Req::as_ptr),
                crl.map_or(core::ptr::null_mut(), Crl::as_ptr),
                flags,
            )
        };
        Self(ctx, core::marker::PhantomData)
    }

    pub fn as_ptr(&mut self) -> *mut X509V3_CTX {
        &mut *self.0
    }

    /// `X509V3_set_nconf(ctx, conf)`.
    pub fn set_nconf(&mut self, conf: &'a crate::conf::Conf) {
        // SAFETY: the context is live; conf outlives the context ('a).
        unsafe { ffi::X509V3_set_nconf(self.as_ptr(), conf.as_ptr()) };
    }

    /// `X509V3_EXT_nconf(NULL, ctx, name, value)`.
    pub fn ext_nconf(&mut self, name: &str, value: &str) -> Option<Extension> {
        let (n, v) = (cstring(name)?, cstring(value)?);
        // SAFETY: the context is live; the strings are valid.
        Extension::from_ptr(unsafe {
            ffi::X509V3_EXT_nconf(core::ptr::null_mut(), self.as_ptr(), n.as_ptr(), v.as_ptr())
        })
    }
}

crate::handle!(
    /// An owned `X509_STORE`.
    Store, X509_STORE, X509_STORE_free
);

/// `X509_load_http(url, NULL, NULL, 0)`.
pub fn load_http_cert(url: &str) -> Option<Cert> {
    let u = cstring(url)?;
    // SAFETY: a valid C string; no BIOs; no timeout.
    Cert::from_raw(unsafe {
        ffi::X509_load_http(u.as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), 0)
    })
}

/// `X509_CRL_load_http(url, NULL, NULL, 0)`.
pub fn load_http_crl(url: &str) -> Option<Crl> {
    let u = cstring(url)?;
    // SAFETY: as above.
    Crl::from_raw(unsafe {
        ffi::X509_CRL_load_http(u.as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), 0)
    })
}

impl Cert {
    /// `X509_get_pubkey`.
    pub fn pubkey(&self) -> Option<Pkey> {
        // SAFETY: the certificate is live; the key is a new reference, ours.
        Pkey::from_raw(unsafe { ffi::X509_get_pubkey(self.as_ptr()) })
    }
}

// PEM certificates and Netscape certificate sequences (`nseq`).

impl Cert {
    /// `PEM_read_bio_X509(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; NULL callback and data use the library's defaults.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_X509(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `X509_up_ref`, as a second owner.
    pub fn up_ref(&self) -> Option<Self> {
        // SAFETY: the certificate is live; the new reference is freed by the new owner.
        (unsafe { ffi::X509_up_ref(self.as_ptr()) } == 1).then(|| Self(self.0))
    }
}

crate::handle!(
    /// An owned `NETSCAPE_CERT_SEQUENCE`.
    CertSeq, NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE_free
);

impl CertSeq {
    /// `NETSCAPE_CERT_SEQUENCE_new()`, with an empty `certs` stack.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        let s = Self::from_ptr(unsafe { ffi::NETSCAPE_CERT_SEQUENCE_new() })?;
        // SAFETY: no arguments.
        let sk = unsafe { ffi::OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
        if sk.is_null() {
            return None;
        }
        // SAFETY: s is live; its `certs` (NULL when new) now owns the stack, freed with it.
        unsafe { (*s.as_ptr()).certs = sk };
        Some(s)
    }

    /// `PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; NULL callback and data use the library's defaults.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_NETSCAPE_CERT_SEQUENCE(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `PEM_write_bio_NETSCAPE_CERT_SEQUENCE`.
    pub fn write_pem(&self, bio: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bio.as_ptr(), self.as_ptr()) == 1 }
    }

    fn certs(&self) -> *mut OPENSSL_STACK {
        // SAFETY: the sequence is live; reading its public field.
        unsafe { (*self.as_ptr()).certs }.cast()
    }

    /// `sk_X509_push(seq->certs, cert)`, which takes the certificate.
    pub fn push(&self, cert: Cert) -> bool {
        let sk = self.certs();
        if sk.is_null() {
            return false;
        }
        // SAFETY: the stack is live; on success it owns the certificate.
        if unsafe { ffi::OPENSSL_sk_push(sk, cert.as_ptr().cast()) } > 0 {
            core::mem::forget(cert);
            true
        } else {
            false
        }
    }

    /// `sk_X509_num(seq->certs)` (-1 for no stack, as the macro returns, read as 0).
    pub fn len(&self) -> usize {
        // SAFETY: the stack is NULL or live; sk_num accepts NULL.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.certs()) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `sk_X509_value(seq->certs, i)`, as a new reference.
    pub fn get(&self, i: usize) -> Option<Cert> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: the stack is NULL or live; sk_value checks the index.
        let p = unsafe { ffi::OPENSSL_sk_value(self.certs(), i) }.cast::<crate::abi::X509>();
        let c = core::ptr::NonNull::new(p)?;
        // SAFETY: c is a live certificate the stack owns; the new reference is ours.
        (unsafe { ffi::X509_up_ref(c.as_ptr()) } == 1).then_some(Cert(c))
    }
}

// Certificate and CRL files as X509_INFO stacks (`rehash`).

unsafe extern "C" fn free_info(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, an X509_INFO.
    unsafe { ffi::X509_INFO_free(p.cast()) };
}

/// What one `X509_INFO` holds.
pub enum InfoKind {
    Cert,
    Crl,
    /// Neither (a key on its own, ...).
    Other,
}

/// An owned `STACK_OF(X509_INFO)`, freed with `sk_X509_INFO_pop_free(sk, X509_INFO_free)`.
pub struct InfoStack(core::ptr::NonNull<crate::abi::stack_st_X509_INFO>);

impl InfoStack {
    /// `PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; NULL makes a new stack; NULL callback and data use the
        // library's defaults.
        let p = unsafe {
            ffi::PEM_X509_INFO_read_bio(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        };
        core::ptr::NonNull::new(p).map(Self)
    }

    fn sk(&self) -> *mut OPENSSL_STACK {
        self.0.as_ptr().cast()
    }

    /// `sk_X509_INFO_num`.
    pub fn len(&self) -> usize {
        // SAFETY: the stack is live.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(self.sk()) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn info(&self, i: usize) -> Option<&crate::abi::X509_INFO> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: the stack is live; sk_value checks the index.
        let p = unsafe { ffi::OPENSSL_sk_value(self.sk(), i) }.cast::<crate::abi::X509_INFO>();
        // SAFETY: p is NULL or a live X509_INFO the stack owns, borrowed with self.
        unsafe { p.as_ref() }
    }

    /// What entry `i` holds.
    pub fn kind(&self, i: usize) -> InfoKind {
        match self.info(i) {
            Some(x) if !x.x509.is_null() => InfoKind::Cert,
            Some(x) if !x.crl.is_null() => InfoKind::Crl,
            _ => InfoKind::Other,
        }
    }

    /// `X509_digest` or `X509_CRL_digest` of entry `i` with `md`.
    pub fn digest(&self, i: usize, md: &crate::evp::Md) -> Option<Vec<u8>> {
        let x = self.info(i)?;
        let mut buf = [0u8; 64];
        let mut len: core::ffi::c_uint = 0;
        let ok = if !x.x509.is_null() {
            // SAFETY: the certificate and digest are live; buf holds EVP_MAX_MD_SIZE bytes.
            unsafe { ffi::X509_digest(x.x509, md.as_ptr(), buf.as_mut_ptr(), &mut len) }
        } else if !x.crl.is_null() {
            // SAFETY: as above, for the CRL.
            unsafe { ffi::X509_CRL_digest(x.crl, md.as_ptr(), buf.as_mut_ptr(), &mut len) }
        } else {
            0
        };
        if ok != 1 {
            return None;
        }
        buf.get(..usize::try_from(len).ok()?).map(<[u8]>::to_vec)
    }

    /// The name entry `i` is filed under: a certificate's subject, a CRL's issuer.
    fn name(&self, i: usize) -> *const X509_NAME {
        match self.info(i) {
            // SAFETY: the certificate is live; the name is owned by it.
            Some(x) if !x.x509.is_null() => unsafe { ffi::X509_get_subject_name(x.x509) },
            // SAFETY: as above, for the CRL.
            Some(x) if !x.crl.is_null() => unsafe { ffi::X509_CRL_get_issuer(x.crl) },
            _ => core::ptr::null_mut(),
        }
    }

    /// `X509_NAME_hash_ex(name, libctx, propq, &ok)` of entry `i`'s name: `None` for no name,
    /// `Some(None)` when it failed.
    pub fn name_hash(
        &self,
        i: usize,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Option<c_ulong>> {
        let n = self.name(i);
        if n.is_null() {
            return None;
        }
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let mut ok: c_int = 0;
        // SAFETY: the name is live; ctx and pq are NULL or valid; ok is a valid out-pointer.
        let h = unsafe {
            ffi::X509_NAME_hash_ex(
                n,
                ctx,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                &mut ok,
            )
        };
        Some((ok != 0).then_some(h))
    }

    /// `X509_NAME_hash_old` of entry `i`'s name (`None` for no name).
    pub fn name_hash_old(&self, i: usize) -> Option<c_ulong> {
        let n = self.name(i);
        // SAFETY: the name is live.
        (!n.is_null()).then(|| unsafe { ffi::X509_NAME_hash_old(n) })
    }
}

impl Drop for InfoStack {
    fn drop(&mut self) {
        // SAFETY: the stack and its entries are owned here and freed once.
        unsafe { ffi::OPENSSL_sk_pop_free(self.sk(), Some(free_info)) };
    }
}

/// `X509_get_default_cert_dir_env()`.
pub fn default_cert_dir_env() -> String {
    // SAFETY: no arguments; the result is a static string.
    string_at(unsafe { ffi::X509_get_default_cert_dir_env() }).unwrap_or_default()
}

/// `X509_get_default_cert_dir()`.
pub fn default_cert_dir() -> String {
    // SAFETY: no arguments; the result is a static string.
    string_at(unsafe { ffi::X509_get_default_cert_dir() }).unwrap_or_default()
}

// ---- The certificate commands (`x509`, `req`, `crl`, `crl2pkcs7`, `ca`, `spkac`, ...).

/// PEM and DER reading and writing for an owned ASN.1 type: `read_pem`/`read_der` (NULL
/// arguments: no callback, no password), `write_pem`/`write_der` (what the call returns).
macro_rules! asn1_io {
    ($ty:ident, $pem_read:ident, $pem_write:ident, $d2i:ident, $i2d:ident) => {
        impl $ty {
            /// `PEM_read_bio_*(bio, NULL, NULL, NULL)`.
            pub fn read_pem_bio(bio: &Bio) -> Option<Self> {
                // SAFETY: the BIO is live; no callback or password.
                Self::from_ptr(unsafe {
                    ffi::$pem_read(
                        bio.as_ptr(),
                        core::ptr::null_mut(),
                        None,
                        core::ptr::null_mut(),
                    )
                })
            }

            /// `d2i_*_bio(bio, NULL)`.
            pub fn read_der_bio(bio: &Bio) -> Option<Self> {
                // SAFETY: the BIO is live.
                Self::from_ptr(unsafe { ffi::$d2i(bio.as_ptr(), core::ptr::null_mut()) })
            }

            /// `PEM_write_bio_*`.
            pub fn write_pem(&self, bio: &Bio) -> c_int {
                // SAFETY: both are live.
                unsafe { ffi::$pem_write(bio.as_ptr(), self.as_ptr()) }
            }

            /// `i2d_*_bio`.
            pub fn write_der(&self, bio: &Bio) -> c_int {
                // SAFETY: both are live.
                unsafe { ffi::$i2d(bio.as_ptr(), self.as_ptr()) }
            }
        }
    };
}

asn1_io!(
    Cert,
    PEM_read_bio_X509,
    PEM_write_bio_X509,
    d2i_X509_bio,
    i2d_X509_bio
);
asn1_io!(
    Crl,
    PEM_read_bio_X509_CRL,
    PEM_write_bio_X509_CRL,
    d2i_X509_CRL_bio,
    i2d_X509_CRL_bio
);
asn1_io!(
    Req,
    PEM_read_bio_X509_REQ,
    PEM_write_bio_X509_REQ,
    d2i_X509_REQ_bio,
    i2d_X509_REQ_bio
);

asn1_io!(
    Pkcs7,
    PEM_read_bio_PKCS7,
    PEM_write_bio_PKCS7,
    d2i_PKCS7_bio,
    i2d_PKCS7_bio
);

impl Pkcs7 {
    /// `crl2pkcs7`'s object: a `signed` PKCS#7 of `data`, version 1, holding `crl` (if any)
    /// and the certificates of `certs` (if any), as `crl2pkcs7.c` builds it.
    pub fn degenerate_signed(crl: Option<Crl>, certs: Option<CertStack>) -> Option<Self> {
        use crate::abi::{NID_pkcs7_data, NID_pkcs7_signed};
        // SAFETY: no arguments.
        let p7 = Self::from_ptr(unsafe { ffi::PKCS7_new() })?;
        // SAFETY: no arguments.
        let p7s = unsafe { ffi::PKCS7_SIGNED_new() };
        if p7s.is_null() {
            return None;
        }
        // SAFETY: no arguments; a static object.
        let signed = unsafe { ffi::OBJ_nid2obj(NID_pkcs7_signed) };
        // SAFETY: as above.
        let data = unsafe { ffi::OBJ_nid2obj(NID_pkcs7_data) };
        // SAFETY: p7 is a live, freshly made public-layout struct.
        let p = unsafe { &mut *p7.as_ptr() };
        p.type_ = signed;
        // The PKCS7 takes p7s, and frees it with itself.
        p.d.sign = p7s;
        // SAFETY: p7s is live, made with its contents and version.
        let s = unsafe { &mut *p7s };
        // SAFETY: the contents are a live PKCS7 of PKCS7_SIGNED_new's.
        let contents = unsafe { &mut *s.contents };
        contents.type_ = data;
        // SAFETY: the version is a live ASN1_INTEGER.
        if unsafe { ffi::ASN1_INTEGER_set(s.version, 1) } != 1 {
            return None;
        }
        if let Some(crl) = crl {
            let crls = CrlStack::new()?;
            // SAFETY: p7s is live; it takes the stack.
            unsafe { (*p7s).crl = crls.as_ptr() };
            let crls = core::mem::ManuallyDrop::new(crls);
            if !crls.push(crl) {
                return None;
            }
        }
        if let Some(certs) = certs {
            // SAFETY: p7s is live; it takes the stack and its certificates.
            unsafe { (*p7s).cert = certs.as_ptr() };
            core::mem::forget(certs);
        }
        Some(p7)
    }
}

impl CertStack {
    /// `sk_X509_push`, which takes the certificate.
    pub fn push(&self, cert: Cert) -> bool {
        // SAFETY: both are live; on success the stack owns the certificate.
        if unsafe { ffi::OPENSSL_sk_push(self.as_ptr().cast(), cert.as_ptr().cast()) } > 0 {
            core::mem::forget(cert);
            true
        } else {
            false
        }
    }

    /// `sk_X509_value(sk, i)`, borrowed.
    pub fn get(&self, i: usize) -> Option<CertRef<'_>> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: the stack is live; out-of-range indices give NULL.
        let p = unsafe { ffi::OPENSSL_sk_value(self.as_ptr().cast(), i) };
        (!p.is_null()).then(|| CertRef(p.cast(), core::marker::PhantomData))
    }
}

/// A certificate borrowed from its owner (a stack, a store context, ...).
#[derive(Clone, Copy)]
pub struct CertRef<'a>(*mut crate::abi::X509, core::marker::PhantomData<&'a ()>);

impl<'a> CertRef<'a> {
    pub(crate) fn new(p: *mut crate::abi::X509) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, core::marker::PhantomData))
    }

    pub fn as_ptr(self) -> *mut crate::abi::X509 {
        self.0
    }

    /// `X509_get_subject_name`.
    pub fn subject_name(self) -> NameRef<'a> {
        // SAFETY: the certificate is live; the name is owned by it.
        NameRef::new(unsafe { ffi::X509_get_subject_name(self.0) })
    }

    /// For each distribution point of the certificate's `nid` extension
    /// (`NID_crl_distribution_points` or `NID_freshest_crl`), its first `http://` URI of
    /// more than 6 bytes, if it has one (`get_dp_url` of `apps.c`).
    pub fn dp_http_urls(self, nid: c_int) -> Vec<Option<String>> {
        use crate::abi::{DIST_POINT, GEN_URI, OPENSSL_STACK};
        // SAFETY: the certificate is live; the stack is the caller's to free.
        let crldp = unsafe {
            ffi::X509_get_ext_d2i(self.0, nid, core::ptr::null_mut(), core::ptr::null_mut())
        }
        .cast::<OPENSSL_STACK>();
        let mut out = Vec::new();
        if crldp.is_null() {
            return out;
        }
        // SAFETY: crldp is live.
        let n = unsafe { ffi::OPENSSL_sk_num(crldp) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each member is a DIST_POINT.
            let dp = unsafe { ffi::OPENSSL_sk_value(crldp, i) }.cast::<DIST_POINT>();
            let mut url = None;
            // SAFETY: dp is live (public layout).
            let dpn = unsafe { (*dp).distpoint };
            // SAFETY: dpn is NULL or a live DIST_POINT_NAME (public layout).
            if !dpn.is_null() && unsafe { (*dpn).type_ } == 0 {
                // SAFETY: dpn is live (checked above).
                let name = unsafe { &(*dpn).name };
                // SAFETY: type 0 is the fullname member of the union.
                let gens = unsafe { name.fullname }.cast::<OPENSSL_STACK>();
                // SAFETY: gens is NULL or live (sk_num of NULL is -1).
                let m = unsafe { ffi::OPENSSL_sk_num(gens) };
                for j in 0..m.max(0) {
                    // SAFETY: j is in range.
                    let gname = unsafe { ffi::OPENSSL_sk_value(gens, j) };
                    let mut gtype: c_int = 0;
                    // SAFETY: gname is a live GENERAL_NAME; gtype a valid out-pointer.
                    let v = unsafe { ffi::GENERAL_NAME_get0_value(gname.cast(), &mut gtype) };
                    if gtype != GEN_URI {
                        continue;
                    }
                    let bytes = asn1_string_bytes(v.cast());
                    if bytes.len() > 6 && bytes.starts_with(b"http://") {
                        url = Some(String::from_utf8_lossy(&bytes).into_owned());
                        break;
                    }
                }
            }
            out.push(url);
        }
        // SAFETY: the stack and its members are owned here and freed once.
        unsafe { ffi::OPENSSL_sk_pop_free(crldp, Some(free_dist_point)) };
        out
    }

    /// A new reference (`X509_up_ref`), owned.
    pub fn to_owned(self) -> Option<Cert> {
        // SAFETY: the certificate is live.
        if unsafe { ffi::X509_up_ref(self.0) } != 1 {
            return None;
        }
        Cert::from_ptr(self.0)
    }
}

/// `PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL)`: the certificates it holds, in order; `None`
/// if it fails.
pub fn pem_x509_info_certs(bio: &Bio) -> Option<Vec<Cert>> {
    // SAFETY: the BIO is live; no callback; the stack and its members are the caller's.
    let sk = unsafe {
        ffi::PEM_X509_INFO_read_bio(
            bio.as_ptr(),
            core::ptr::null_mut(),
            None,
            core::ptr::null_mut(),
        )
    };
    if sk.is_null() {
        return None;
    }
    let st = sk.cast::<OPENSSL_STACK>();
    let mut out = Vec::new();
    // SAFETY: st is live.
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; each member is an X509_INFO.
        let xi = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<crate::abi::X509_INFO>();
        if xi.is_null() {
            continue;
        }
        // SAFETY: xi is a live X509_INFO.
        let info = unsafe { &mut *xi };
        // Its certificate moves to `out`, and the field is cleared so X509_INFO_free doesn't
        // free it.
        if let Some(c) = Cert::from_ptr(info.x509) {
            out.push(c);
        }
        info.x509 = core::ptr::null_mut();
        // SAFETY: xi is owned here and freed once.
        unsafe { ffi::X509_INFO_free(xi) };
    }
    // SAFETY: the members are freed; only the stack is left.
    unsafe { ffi::OPENSSL_sk_free(st) };
    Some(out)
}

crate::handle!(
    /// An owned `NETSCAPE_SPKI`.
    Spki, NETSCAPE_SPKI, NETSCAPE_SPKI_free
);

impl Spki {
    /// `NETSCAPE_SPKI_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::NETSCAPE_SPKI_new() })
    }

    /// `ASN1_STRING_set(spki->spkac->challenge, challenge, len)`.
    pub fn set_challenge(&self, challenge: &[u8]) -> bool {
        let Ok(len) = c_int::try_from(challenge.len()) else {
            return false;
        };
        // SAFETY: the SPKI is live, with its spkac made by NETSCAPE_SPKI_new.
        let spkac = unsafe { (*self.as_ptr()).spkac };
        if spkac.is_null() {
            return false;
        }
        // SAFETY: spkac is live, its challenge made with it.
        let ch = unsafe { (*spkac).challenge };
        // SAFETY: ch is live; challenge is valid for len bytes.
        unsafe { ffi::ASN1_STRING_set(ch, challenge.as_ptr().cast(), len) == 1 }
    }

    /// `NETSCAPE_SPKI_set_pubkey`.
    pub fn set_pubkey(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::NETSCAPE_SPKI_set_pubkey(self.as_ptr(), pkey.as_ptr()) == 1 }
    }

    /// `NETSCAPE_SPKI_sign`: what it returns.
    pub fn sign(&self, pkey: &Pkey, md: &crate::evp::Md) -> c_int {
        // SAFETY: all are live.
        unsafe { ffi::NETSCAPE_SPKI_sign(self.as_ptr(), pkey.as_ptr(), md.as_ptr()) }
    }

    /// `NETSCAPE_SPKI_b64_encode`.
    pub fn b64_encode(&self) -> Option<String> {
        // SAFETY: the SPKI is live; the string is the caller's to free.
        take_string(unsafe { ffi::NETSCAPE_SPKI_b64_encode(self.as_ptr()) })
    }

    /// `NETSCAPE_SPKI_b64_decode(s, -1)`.
    pub fn b64_decode(s: &str) -> Option<Self> {
        let c = cstring(s)?;
        // SAFETY: c is a valid C string (its length is taken with strlen).
        Self::from_ptr(unsafe { ffi::NETSCAPE_SPKI_b64_decode(c.as_ptr(), -1) })
    }

    /// `NETSCAPE_SPKI_print`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::NETSCAPE_SPKI_print(out.as_ptr(), self.as_ptr()) }
    }

    /// `NETSCAPE_SPKI_get_pubkey`.
    pub fn pubkey(&self) -> Option<Pkey> {
        // SAFETY: the SPKI is live; the key is a new reference.
        Pkey::from_raw(unsafe { ffi::NETSCAPE_SPKI_get_pubkey(self.as_ptr()) })
    }

    /// `NETSCAPE_SPKI_verify(spki, pkey)` (NULL key allowed): what it returns.
    pub fn verify(&self, pkey: Option<&Pkey>) -> c_int {
        // SAFETY: the SPKI is live; the key is live or NULL.
        unsafe {
            ffi::NETSCAPE_SPKI_verify(
                self.as_ptr(),
                pkey.map_or(core::ptr::null_mut(), Pkey::as_ptr),
            )
        }
    }
}

/// `Some(CString)` for `Some`, `Some(None)` for `None`, `None` if the string holds a NUL.
fn opt_cstring(s: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    }
}

/// The pointer of an optional C string (NULL for `None`).
fn opt_ptr(s: &Option<std::ffi::CString>) -> *const core::ffi::c_char {
    s.as_ref().map_or(core::ptr::null(), |s| s.as_ptr())
}

/// The bytes of a live `ASN1_STRING` (empty for NULL).
pub(crate) fn asn1_string_bytes(s: *const crate::abi::ASN1_STRING) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    // SAFETY: s is a live ASN1_STRING.
    let d = unsafe { ffi::ASN1_STRING_get0_data(s) };
    // SAFETY: as above.
    let n = usize::try_from(unsafe { ffi::ASN1_STRING_length(s) }).unwrap_or(0);
    if d.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: the string's data is valid for its length while it lives.
    unsafe { core::slice::from_raw_parts(d, n) }.to_vec()
}

/// An `ASN1_TIME` borrowed from its owner.
#[derive(Clone, Copy)]
pub struct TimeRef<'a>(
    *const crate::abi::ASN1_TIME,
    core::marker::PhantomData<&'a ()>,
);

impl TimeRef<'_> {
    fn new(p: *const crate::abi::ASN1_TIME) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, core::marker::PhantomData))
    }

    pub fn as_ptr(self) -> *const crate::abi::ASN1_TIME {
        self.0
    }

    /// `ASN1_TIME_print_ex(out, t, flags)`.
    pub fn print_ex(self, out: &Bio, flags: c_ulong) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::ASN1_TIME_print_ex(out.as_ptr(), self.0, flags) }
    }

    /// `X509_cmp_time(t, NULL)`: -1 or 0 if `t` is before now (0 on error), 1 if after.
    pub fn cmp_now(self) -> c_int {
        // SAFETY: the time is live; NULL means now.
        unsafe { ffi::X509_cmp_time(self.0, core::ptr::null_mut()) }
    }

    /// `X509_cmp_time(t, &when)`.
    pub fn cmp_time(self, when: libc::time_t) -> c_int {
        let mut w = when;
        // SAFETY: the time is live; w is a valid time_t.
        unsafe { ffi::X509_cmp_time(self.0, &mut w) }
    }

    /// The time's string and type (`ASN1_STRING_get0_data`, `ASN1_STRING_type`).
    pub fn data(self) -> (Vec<u8>, c_int) {
        // SAFETY: the time is a live ASN1_STRING.
        let ty = unsafe { ffi::ASN1_STRING_type(self.0) };
        (asn1_string_bytes(self.0), ty)
    }
}

crate::handle!(
    /// An owned `ASN1_TIME`.
    Time, ASN1_TIME, ASN1_TIME_free
);

impl Time {
    pub fn as_ref(&self) -> TimeRef<'_> {
        TimeRef(self.as_ptr(), core::marker::PhantomData)
    }

    /// `ASN1_TIME_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::ASN1_TIME_new() })
    }

    /// `ASN1_TIME_set_string_X509(t, s)`.
    pub fn set_string_x509(&self, s: &str) -> bool {
        let Some(c) = cstring(s) else {
            return false;
        };
        // SAFETY: the time is live; c is a valid C string.
        unsafe { ffi::ASN1_TIME_set_string_X509(self.as_ptr(), c.as_ptr()) == 1 }
    }

    /// `ASN1_TIME_set_string(t, s)`.
    pub fn set_string(&self, s: &str) -> bool {
        let Some(c) = cstring(s) else {
            return false;
        };
        // SAFETY: as above.
        unsafe { ffi::ASN1_TIME_set_string(self.as_ptr(), c.as_ptr()) == 1 }
    }

    /// `X509_time_adj_ex(t, days, secs, NULL)`: false on failure.
    pub fn adj_now(&self, days: c_int, secs: c_long) -> bool {
        // SAFETY: the time is live; NULL means now.
        !unsafe { ffi::X509_time_adj_ex(self.as_ptr(), days, secs, core::ptr::null_mut()) }
            .is_null()
    }

    /// `ASN1_TIME_adj(NULL, t, days, secs)`, a new time.
    pub fn new_adj(t: libc::time_t, days: c_int, secs: c_long) -> Option<Self> {
        // SAFETY: NULL asks for a new time.
        Self::from_ptr(unsafe { ffi::ASN1_TIME_adj(core::ptr::null_mut(), t, days, secs) })
    }

    /// `ASN1_TIME_to_generalizedtime(t, NULL)`... as `ASN1_GENERALIZEDTIME`, a new time.
    pub fn to_generalized(&self) -> Option<Self> {
        // SAFETY: the time is live; NULL asks for a new one.
        Self::from_ptr(unsafe {
            ffi::ASN1_TIME_to_generalizedtime(self.as_ptr(), core::ptr::null_mut())
        })
    }
}

crate::handle!(
    /// An owned `ASN1_INTEGER`.
    Integer, ASN1_INTEGER, ASN1_INTEGER_free
);

impl Integer {
    /// `ASN1_INTEGER_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::ASN1_INTEGER_new() })
    }

    /// `s2i_ASN1_INTEGER(NULL, s)`.
    pub fn from_dec_or_hex(s: &str) -> Option<Self> {
        let c = cstring(s)?;
        // SAFETY: NULL method is allowed; c is a valid C string.
        Self::from_ptr(unsafe { ffi::s2i_ASN1_INTEGER(core::ptr::null_mut(), c.as_ptr()) })
    }

    /// `i2a_ASN1_INTEGER(out, a)`.
    pub fn i2a(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2a_ASN1_INTEGER(out.as_ptr(), self.as_ptr()) }
    }

    /// `BN_to_ASN1_INTEGER(bn, NULL)`.
    pub fn from_bn(bn: &Bn) -> Option<Self> {
        // SAFETY: bn is live; NULL asks for a new integer.
        Self::from_ptr(unsafe { ffi::BN_to_ASN1_INTEGER(bn.as_ptr(), core::ptr::null_mut()) })
    }

    /// `ASN1_INTEGER_to_BN(a, NULL)`.
    pub fn to_bn(&self) -> Option<Bn> {
        // SAFETY: the integer is live; NULL asks for a new BIGNUM.
        Bn::from_ptr(unsafe { ffi::ASN1_INTEGER_to_BN(self.as_ptr(), core::ptr::null_mut()) })
    }

    /// `ASN1_INTEGER_set(a, v)`.
    pub fn set(&self, v: c_long) -> bool {
        // SAFETY: the integer is live.
        unsafe { ffi::ASN1_INTEGER_set(self.as_ptr(), v) == 1 }
    }
}

impl NameRef<'_> {
    pub fn as_ptr(self) -> *const X509_NAME {
        self.0
    }

    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    /// `X509_NAME_hash_ex(nm, libctx, propq, &ok)`: the hash and `ok`.
    pub fn hash_ex(self, libctx: Option<&LibCtx>, propq: Option<&str>) -> (c_ulong, bool) {
        let Some(pq) = opt_cstring(propq) else {
            return (0, false);
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let mut ok: c_int = 0;
        // SAFETY: the name is live; ok is a valid out-pointer.
        let h = unsafe { ffi::X509_NAME_hash_ex(self.0, ctx, opt_ptr(&pq), &mut ok) };
        (h, ok != 0)
    }

    /// `X509_NAME_hash_old`.
    pub fn hash_old(self) -> c_ulong {
        // SAFETY: the name is live.
        unsafe { ffi::X509_NAME_hash_old(self.0) }
    }

    /// `X509_NAME_dup`.
    pub fn to_owned(self) -> Option<Name> {
        // SAFETY: the name is live.
        Name::from_ptr(unsafe { ffi::X509_NAME_dup(self.0) })
    }

    /// `X509_NAME_cmp`.
    pub fn name_cmp(self, other: NameRef<'_>) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_NAME_cmp(self.0, other.0) }
    }

    /// `X509_NAME_entry_count`.
    pub fn entry_count(self) -> c_int {
        // SAFETY: the name is live.
        unsafe { ffi::X509_NAME_entry_count(self.0) }
    }
}

crate::handle!(
    /// An owned `X509_OBJECT`.
    Object, X509_OBJECT, X509_OBJECT_free
);

impl Object {
    /// `X509_get_pubkey(X509_OBJECT_get0_X509(obj))`.
    pub fn cert_pubkey(&self) -> Option<Pkey> {
        // SAFETY: the object is live; the certificate is owned by it (NULL if it isn't one).
        let x = unsafe { ffi::X509_OBJECT_get0_X509(self.as_ptr()) };
        // SAFETY: x is live or NULL, which X509_get_pubkey accepts; the key is a new reference.
        Pkey::from_raw(unsafe { ffi::X509_get_pubkey(x) })
    }
}

/// The digest of an object (`X509_digest`, `X509_CRL_digest`, ...), as bytes.
fn digest_with(
    f: impl FnOnce(*mut core::ffi::c_uchar, *mut core::ffi::c_uint) -> c_int,
) -> Option<Vec<u8>> {
    let mut md = [0u8; crate::abi::EVP_MAX_MD_SIZE as usize];
    let mut n: core::ffi::c_uint = 0;
    if f(md.as_mut_ptr(), &mut n) == 0 {
        return None;
    }
    md.get(..usize::try_from(n).ok()?).map(<[u8]>::to_vec)
}

/// `corrupt_signature` of `apps.c`: flips the last bit of a signature.
fn corrupt(sig: *const crate::abi::ASN1_BIT_STRING) {
    if sig.is_null() {
        return;
    }
    // SAFETY: sig is the object's own, live signature.
    let s = unsafe { &*sig };
    if s.length <= 0 || s.data.is_null() {
        return;
    }
    let last = usize::try_from(s.length - 1).unwrap_or(0);
    // SAFETY: data holds `length` bytes; the C API hands the signature out const, but upstream
    // writes to it in place, as here.
    let byte = unsafe { s.data.add(last) };
    // SAFETY: byte is within the signature's data.
    unsafe { *byte ^= 1 };
}

impl Crl {
    /// `X509_CRL_get_issuer`.
    pub fn issuer_name(&self) -> NameRef<'_> {
        // SAFETY: the CRL is live; the name is owned by it.
        NameRef::new(unsafe { ffi::X509_CRL_get_issuer(self.as_ptr()) })
    }

    /// `X509_CRL_get_ext_d2i(crl, nid, NULL, NULL)` for an `ASN1_INTEGER` extension.
    pub fn ext_integer(&self, nid: c_int) -> Option<Integer> {
        // SAFETY: the CRL is live; for these NIDs the result is an ASN1_INTEGER the caller
        // frees.
        Integer::from_ptr(
            unsafe {
                ffi::X509_CRL_get_ext_d2i(
                    self.as_ptr(),
                    nid,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            }
            .cast(),
        )
    }

    /// `X509_CRL_get0_lastUpdate`.
    pub fn last_update(&self) -> Option<TimeRef<'_>> {
        // SAFETY: the CRL is live; the time is owned by it.
        TimeRef::new(unsafe { ffi::X509_CRL_get0_lastUpdate(self.as_ptr()) })
    }

    /// `X509_CRL_get0_nextUpdate`.
    pub fn next_update(&self) -> Option<TimeRef<'_>> {
        // SAFETY: as above.
        TimeRef::new(unsafe { ffi::X509_CRL_get0_nextUpdate(self.as_ptr()) })
    }

    /// `X509_CRL_digest`.
    pub fn digest(&self, md: &crate::evp::Md) -> Option<Vec<u8>> {
        // SAFETY: the CRL and digest are live; the buffers are valid.
        digest_with(|b, n| unsafe { ffi::X509_CRL_digest(self.as_ptr(), md.as_ptr(), b, n) })
    }

    /// `X509_CRL_print_ex`.
    pub fn print_ex(&self, out: &Bio, nmflag: c_ulong) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_CRL_print_ex(out.as_ptr(), self.as_ptr(), nmflag) }
    }

    /// `X509_CRL_verify`.
    pub fn verify(&self, pkey: &Pkey) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_CRL_verify(self.as_ptr(), pkey.as_ptr()) }
    }

    /// `X509_CRL_diff(self, newer, pkey, md, flags)`.
    pub fn diff(
        &self,
        newer: &Crl,
        pkey: &Pkey,
        md: &crate::evp::Md,
        flags: core::ffi::c_uint,
    ) -> Option<Crl> {
        // SAFETY: all are live.
        Crl::from_ptr(unsafe {
            ffi::X509_CRL_diff(
                self.as_ptr(),
                newer.as_ptr(),
                pkey.as_ptr(),
                md.as_ptr(),
                flags,
            )
        })
    }

    /// `corrupt_signature` of the CRL's signature.
    pub fn corrupt_signature(&self) {
        let mut sig: *const crate::abi::ASN1_BIT_STRING = core::ptr::null();
        // SAFETY: the CRL is live; sig is a valid out-pointer.
        unsafe { ffi::X509_CRL_get0_signature(self.as_ptr(), &mut sig, core::ptr::null_mut()) };
        corrupt(sig);
    }
}

impl Cert {
    /// `X509_print`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_print(out.as_ptr(), self.as_ptr()) }
    }
}

impl Crl {
    /// `X509_CRL_print`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_CRL_print(out.as_ptr(), self.as_ptr()) }
    }
}

/// `OBJ_nid2sn(nid)`.
pub fn nid2sn(nid: c_int) -> Option<String> {
    // SAFETY: any NID; the string is static.
    string_at(unsafe { ffi::OBJ_nid2sn(nid) })
}

/// `OBJ_nid2ln(nid)`.
pub fn nid2ln(nid: c_int) -> Option<String> {
    // SAFETY: as above.
    string_at(unsafe { ffi::OBJ_nid2ln(nid) })
}

/// `OBJ_sn2nid`.
pub fn sn2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: a valid C string.
    unsafe { ffi::OBJ_sn2nid(c.as_ptr()) }
}

/// An extension borrowed from its owner.
#[derive(Clone, Copy)]
pub struct ExtRef<'a>(*mut X509_EXTENSION, core::marker::PhantomData<&'a ()>);

impl ExtRef<'_> {
    pub fn as_ptr(self) -> *mut X509_EXTENSION {
        self.0
    }

    /// `OBJ_obj2nid(X509_EXTENSION_get_object(ex))`.
    pub fn nid(self) -> c_int {
        // SAFETY: the extension is live; the object is owned by it.
        let obj = unsafe { ffi::X509_EXTENSION_get_object(self.0) };
        // SAFETY: obj is live.
        unsafe { ffi::OBJ_obj2nid(obj) }
    }

    /// The short name of its type (`OBJ_nid2sn`), as C has it (NULL for none).
    pub fn sn(self) -> Option<String> {
        nid2sn(self.nid())
    }

    /// `X509_EXTENSION_get_critical`.
    pub fn critical(self) -> bool {
        // SAFETY: the extension is live.
        unsafe { ffi::X509_EXTENSION_get_critical(self.0) > 0 }
    }
}

impl Extension {
    pub fn as_ext(&self) -> ExtRef<'_> {
        ExtRef(self.as_ptr(), core::marker::PhantomData)
    }
}

/// A temporary `STACK_OF(X509_EXTENSION)` of borrowed extensions (freed without them).
struct ExtList(*mut OPENSSL_STACK);

impl ExtList {
    fn new(exts: &[ExtRef<'_>]) -> Option<Self> {
        // SAFETY: no arguments.
        let st = unsafe { ffi::OPENSSL_sk_new_null() };
        if st.is_null() {
            return None;
        }
        let list = Self(st);
        for e in exts {
            // SAFETY: the stack is live; it only borrows e.
            if unsafe { ffi::OPENSSL_sk_push(st, e.0.cast()) } <= 0 {
                return None;
            }
        }
        Some(list)
    }

    fn as_ptr(&self) -> *const crate::abi::stack_st_X509_EXTENSION {
        self.0.cast()
    }
}

impl Drop for ExtList {
    fn drop(&mut self) {
        // SAFETY: the stack is owned here; its members are borrowed, not freed.
        unsafe { ffi::OPENSSL_sk_free(self.0) };
    }
}

/// `X509V3_extensions_print(out, NULL, exts, flag, indent)`.
pub fn extensions_print(out: &Bio, exts: &[ExtRef<'_>], flag: c_ulong, indent: c_int) -> c_int {
    let Some(list) = ExtList::new(exts) else {
        return 0;
    };
    // SAFETY: both are live; no title.
    unsafe {
        ffi::X509V3_extensions_print(out.as_ptr(), core::ptr::null(), list.as_ptr(), flag, indent)
    }
}

/// The strings of a `STACK_OF(OPENSSL_STRING)`, freed with `X509_email_free`.
fn take_strings(sk: *mut crate::abi::stack_st_OPENSSL_STRING) -> Vec<String> {
    let st = sk.cast::<OPENSSL_STACK>();
    let mut out = Vec::new();
    // SAFETY: st is NULL or live (sk_num of NULL is -1).
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; each member is a C string.
        let s = unsafe { ffi::OPENSSL_sk_value(st, i) };
        if let Some(s) = string_at(s.cast()) {
            out.push(s);
        }
    }
    // SAFETY: the stack and its strings are owned here (NULL allowed).
    unsafe { ffi::X509_email_free(sk) };
    out
}

/// The certificate's purposes: (id, name) of each `X509_PURPOSE`.
pub fn purpose_ids() -> Vec<(c_int, String)> {
    // SAFETY: no arguments.
    let n = unsafe { ffi::X509_PURPOSE_get_count() };
    let mut out = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: i is in range.
        let p = unsafe { ffi::X509_PURPOSE_get0(i) };
        if p.is_null() {
            continue;
        }
        // SAFETY: p is live.
        let id = unsafe { ffi::X509_PURPOSE_get_id(p) };
        // SAFETY: p is live; the name is owned by it.
        let name = string_at(unsafe { ffi::X509_PURPOSE_get0_name(p) }).unwrap_or_default();
        out.push((id, name));
    }
    out
}

impl Cert {
    /// `X509_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = opt_cstring(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; pq is NULL or a valid C string.
        Self::from_ptr(unsafe { ffi::X509_new_ex(ctx, opt_ptr(&pq)) })
    }

    /// Borrows the certificate.
    pub fn as_cert(&self) -> CertRef<'_> {
        CertRef(self.as_ptr(), core::marker::PhantomData)
    }

    /// `X509_set_subject_name`.
    pub fn set_subject_name(&self, nm: NameRef<'_>) -> bool {
        // SAFETY: both are live; the certificate copies the name.
        unsafe { ffi::X509_set_subject_name(self.as_ptr(), nm.0) == 1 }
    }

    /// `X509_set_issuer_name`.
    pub fn set_issuer_name(&self, nm: NameRef<'_>) -> bool {
        // SAFETY: as above.
        unsafe { ffi::X509_set_issuer_name(self.as_ptr(), nm.0) == 1 }
    }

    /// `X509_set_pubkey`.
    pub fn set_pubkey(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live; the certificate takes its own reference.
        unsafe { ffi::X509_set_pubkey(self.as_ptr(), pkey.as_ptr()) == 1 }
    }

    /// `X509_alias_set1(x, alias, -1)`.
    pub fn alias_set1(&self, alias: &str) -> bool {
        let Some(c) = cstring(alias) else {
            return false;
        };
        // SAFETY: the certificate is live; c is NUL-terminated (length -1).
        unsafe { ffi::X509_alias_set1(self.as_ptr(), c.as_ptr().cast(), -1) == 1 }
    }

    /// `X509_alias_get0`: the alias (up to a NUL, as `%s` prints it).
    pub fn alias(&self) -> Option<Vec<u8>> {
        let mut len: c_int = 0;
        // SAFETY: the certificate is live; len is a valid out-pointer.
        let p = unsafe { ffi::X509_alias_get0(self.as_ptr(), &mut len) };
        if p.is_null() {
            return None;
        }
        let n = usize::try_from(len).unwrap_or(0);
        // SAFETY: the alias holds len bytes, owned by the certificate.
        let bytes = unsafe { core::slice::from_raw_parts(p, n) };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(bytes.get(..end).unwrap_or_default().to_vec())
    }

    /// `X509_trust_clear`.
    pub fn trust_clear(&self) {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_trust_clear(self.as_ptr()) };
    }

    /// `X509_reject_clear`.
    pub fn reject_clear(&self) {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_reject_clear(self.as_ptr()) };
    }

    /// `X509_add1_trust_object`.
    pub fn add1_trust_object(&self, obj: &Obj) -> bool {
        // SAFETY: both are live; the certificate copies the object.
        unsafe { ffi::X509_add1_trust_object(self.as_ptr(), obj.as_ptr()) == 1 }
    }

    /// `X509_add1_reject_object`.
    pub fn add1_reject_object(&self, obj: &Obj) -> bool {
        // SAFETY: as above.
        unsafe { ffi::X509_add1_reject_object(self.as_ptr(), obj.as_ptr()) == 1 }
    }

    /// `X509_get_ext_count`.
    pub fn ext_count(&self) -> c_int {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_get_ext_count(self.as_ptr()) }
    }

    /// `X509_get_ext(x, i)`, borrowed.
    pub fn ext(&self, i: c_int) -> Option<ExtRef<'_>> {
        // SAFETY: the certificate is live; out-of-range gives NULL.
        let e = unsafe { ffi::X509_get_ext(self.as_ptr(), i) };
        (!e.is_null()).then_some(ExtRef(e, core::marker::PhantomData))
    }

    /// The certificate's extensions, borrowed, in order.
    pub fn extensions(&self) -> Vec<ExtRef<'_>> {
        (0..self.ext_count().max(0))
            .filter_map(|i| self.ext(i))
            .collect()
    }

    /// `X509_set_serialNumber` (the certificate copies it).
    pub fn set_serial(&self, sn: &Integer) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::X509_set_serialNumber(self.as_ptr(), sn.as_ptr()) == 1 }
    }

    /// `X509_get0_serialNumber`, copied.
    pub fn serial(&self) -> Option<Integer> {
        // SAFETY: the certificate is live; the serial is owned by it.
        let s = unsafe { ffi::X509_get0_serialNumber(self.as_ptr()) };
        if s.is_null() {
            return None;
        }
        // SAFETY: s is live; the copy is the caller's.
        Integer::from_ptr(unsafe { ffi::ASN1_INTEGER_dup(s) })
    }

    /// `X509_get0_notBefore`.
    pub fn not_before(&self) -> Option<TimeRef<'_>> {
        // SAFETY: the certificate is live; the time is owned by it.
        TimeRef::new(unsafe { ffi::X509_get0_notBefore(self.as_ptr()) })
    }

    /// `X509_get0_notAfter`.
    pub fn not_after(&self) -> Option<TimeRef<'_>> {
        // SAFETY: as above.
        TimeRef::new(unsafe { ffi::X509_get0_notAfter(self.as_ptr()) })
    }

    /// `X509_gmtime_adj(X509_getm_notBefore(x), 0)` (`true`) or
    /// `ASN1_TIME_set_string_X509(X509_getm_notBefore(x), s)`.
    pub fn set_not_before(&self, s: Option<&str>) -> bool {
        // SAFETY: the certificate is live; the time is owned by it.
        let t = unsafe { ffi::X509_getm_notBefore(self.as_ptr()) };
        set_time(t, s, 0)
    }

    /// `X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)` for `None`, else
    /// `ASN1_TIME_set_string_X509(X509_getm_notAfter(x), s)`.
    pub fn set_not_after(&self, s: Option<&str>, days: c_int) -> bool {
        // SAFETY: the certificate is live; the time is owned by it.
        let t = unsafe { ffi::X509_getm_notAfter(self.as_ptr()) };
        set_time(t, s, days)
    }

    /// `X509_set1_notBefore`.
    pub fn set1_not_before(&self, t: TimeRef<'_>) -> bool {
        // SAFETY: both are live; the certificate copies the time.
        unsafe { ffi::X509_set1_notBefore(self.as_ptr(), t.0) == 1 }
    }

    /// `X509_set1_notAfter`.
    pub fn set1_not_after(&self, t: TimeRef<'_>) -> bool {
        // SAFETY: as above.
        unsafe { ffi::X509_set1_notAfter(self.as_ptr(), t.0) == 1 }
    }

    /// `X509_get1_email`.
    pub fn emails(&self) -> Vec<String> {
        // SAFETY: the certificate is live; the stack is the caller's.
        take_strings(unsafe { ffi::X509_get1_email(self.as_ptr()) })
    }

    /// `X509_get1_ocsp`.
    pub fn ocsp_uris(&self) -> Vec<String> {
        // SAFETY: as above.
        take_strings(unsafe { ffi::X509_get1_ocsp(self.as_ptr()) })
    }

    /// `X509_subject_name_hash`.
    pub fn subject_name_hash(&self) -> c_ulong {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_subject_name_hash(self.as_ptr()) }
    }

    /// `X509_subject_name_hash_old`.
    pub fn subject_name_hash_old(&self) -> c_ulong {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_subject_name_hash_old(self.as_ptr()) }
    }

    /// `X509_issuer_name_hash`.
    pub fn issuer_name_hash(&self) -> c_ulong {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_issuer_name_hash(self.as_ptr()) }
    }

    /// `X509_issuer_name_hash_old`.
    pub fn issuer_name_hash_old(&self) -> c_ulong {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_issuer_name_hash_old(self.as_ptr()) }
    }

    /// `X509_check_purpose(x, id, ca)`.
    pub fn check_purpose(&self, id: c_int, ca: c_int) -> c_int {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_check_purpose(self.as_ptr(), id, ca) }
    }

    /// `X509_print_ex`.
    pub fn print_ex(&self, out: &Bio, nmflag: c_ulong, cflag: c_ulong) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_print_ex(out.as_ptr(), self.as_ptr(), nmflag, cflag) }
    }

    /// `X509_digest`.
    pub fn digest(&self, md: &crate::evp::Md) -> Option<Vec<u8>> {
        // SAFETY: the certificate and digest are live; the buffers are valid.
        digest_with(|b, n| unsafe { ffi::X509_digest(self.as_ptr(), md.as_ptr(), b, n) })
    }

    /// `X509_ocspid_print`.
    pub fn ocspid_print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_ocspid_print(out.as_ptr(), self.as_ptr()) }
    }

    /// `X509_check_host(x, host, 0, 0, NULL)`.
    pub fn check_host(&self, host: &str) -> c_int {
        let Some(c) = cstring(host) else {
            return -2;
        };
        // SAFETY: the certificate is live; c is a valid C string (length 0: strlen).
        unsafe { ffi::X509_check_host(self.as_ptr(), c.as_ptr(), 0, 0, core::ptr::null_mut()) }
    }

    /// `X509_check_email(x, email, 0, 0)`.
    pub fn check_email(&self, email: &str) -> c_int {
        let Some(c) = cstring(email) else {
            return -2;
        };
        // SAFETY: as above.
        unsafe { ffi::X509_check_email(self.as_ptr(), c.as_ptr(), 0, 0) }
    }

    /// `X509_check_ip_asc(x, ip, 0)`.
    pub fn check_ip_asc(&self, ip: &str) -> c_int {
        let Some(c) = cstring(ip) else {
            return -2;
        };
        // SAFETY: as above.
        unsafe { ffi::X509_check_ip_asc(self.as_ptr(), c.as_ptr(), 0) }
    }

    /// `PEM_write_bio_X509_AUX`.
    pub fn write_pem_aux(&self, bio: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_X509_AUX(bio.as_ptr(), self.as_ptr()) }
    }

    /// `corrupt_signature` of the certificate's signature.
    pub fn corrupt_signature(&self) {
        let mut sig: *const crate::abi::ASN1_BIT_STRING = core::ptr::null();
        // SAFETY: the certificate is live; sig is a valid out-pointer.
        unsafe { ffi::X509_get0_signature(&mut sig, core::ptr::null_mut(), self.as_ptr()) };
        corrupt(sig);
    }

    /// `X509_to_X509_REQ(x, NULL, NULL)`.
    pub fn to_req(&self) -> Option<Req> {
        // SAFETY: the certificate is live; no key or digest.
        Req::from_ptr(unsafe {
            ffi::X509_to_X509_REQ(self.as_ptr(), core::ptr::null_mut(), core::ptr::null())
        })
    }

    /// Whether `X509_get0_pubkey` is non-NULL.
    pub fn has_pubkey(&self) -> bool {
        // SAFETY: the certificate is live; the key is owned by it.
        !unsafe { ffi::X509_get0_pubkey(self.as_ptr()) }.is_null()
    }

    /// `X509_get_version`.
    pub fn version(&self) -> c_long {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_get_version(self.as_ptr()) }
    }

    /// `X509_cmp`.
    pub fn x509_cmp(&self, other: &Cert) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_cmp(self.as_ptr(), other.as_ptr()) }
    }
}

/// Sets a time the object owns: now plus `days` (`X509_time_adj_ex`, `days` 0 for
/// `X509_gmtime_adj(t, 0)`), or `s`.
fn set_time(t: *mut crate::abi::ASN1_TIME, s: Option<&str>, days: c_int) -> bool {
    match s {
        None => {
            // SAFETY: t is the object's live time; NULL means now.
            !unsafe { ffi::X509_time_adj_ex(t, days, 0, core::ptr::null_mut()) }.is_null()
        }
        Some(s) => {
            let Some(c) = cstring(s) else {
                return false;
            };
            // SAFETY: t is live; c a valid C string.
            unsafe { ffi::ASN1_TIME_set_string_X509(t, c.as_ptr()) == 1 }
        }
    }
}

/// `ASN1_TIME_set_string_X509(NULL, s)`: whether `s` is a valid time.
pub fn time_string_ok(s: &str) -> bool {
    let Some(c) = cstring(s) else {
        return false;
    };
    // SAFETY: NULL only checks the string.
    unsafe { ffi::ASN1_TIME_set_string_X509(core::ptr::null_mut(), c.as_ptr()) == 1 }
}

/// `ASN1_TIME_compare`.
pub fn time_compare(a: TimeRef<'_>, b: TimeRef<'_>) -> c_int {
    // SAFETY: both are live.
    unsafe { ffi::ASN1_TIME_compare(a.0, b.0) }
}

impl Req {
    /// `X509_REQ_get_subject_name`.
    pub fn subject_name(&self) -> NameRef<'_> {
        // SAFETY: the request is live; the name is owned by it.
        NameRef::new(unsafe { ffi::X509_REQ_get_subject_name(self.as_ptr()) })
    }

    /// `X509_REQ_add_extensions(req, exts)` (the request copies them).
    pub fn add_extensions(&self, exts: &[ExtRef<'_>]) -> bool {
        let Some(list) = ExtList::new(exts) else {
            return false;
        };
        // SAFETY: both are live.
        unsafe { ffi::X509_REQ_add_extensions(self.as_ptr(), list.as_ptr()) == 1 }
    }

    /// `X509_REQ_print_ex`.
    pub fn print_ex(&self, out: &Bio, nmflag: c_ulong, cflag: c_ulong) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::X509_REQ_print_ex(out.as_ptr(), self.as_ptr(), nmflag, cflag) }
    }
}

impl<'a> V3Ctx<'a> {
    /// `X509V3_set_ctx_test`: a context for checking a configuration's extensions.
    /// (The macro is `X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, X509V3_CTX_TEST)`.)
    pub fn test() -> Self {
        Self::new(None, None, None, None, crate::abi::X509V3_CTX_TEST)
    }

    /// `X509V3_set_issuer_pkey` (NULL allowed).
    pub fn set_issuer_pkey(&mut self, pkey: Option<&'a Pkey>) -> bool {
        // SAFETY: the context is live; the key outlives it ('a) or is NULL.
        unsafe {
            ffi::X509V3_set_issuer_pkey(
                self.as_ptr(),
                pkey.map_or(core::ptr::null_mut(), Pkey::as_ptr),
            ) == 1
        }
    }

    /// `X509V3_EXT_add_nconf(conf, ctx, section, cert)`.
    pub fn add_nconf(
        &mut self,
        conf: &crate::conf::Conf,
        section: &str,
        cert: Option<&Cert>,
    ) -> bool {
        let Some(s) = cstring(section) else {
            return false;
        };
        // SAFETY: all are live or NULL.
        unsafe {
            ffi::X509V3_EXT_add_nconf(
                conf.as_ptr(),
                self.as_ptr(),
                s.as_ptr(),
                cert.map_or(core::ptr::null_mut(), Cert::as_ptr),
            ) == 1
        }
    }

    /// `X509V3_EXT_REQ_add_nconf(conf, ctx, section, req)`.
    pub fn req_add_nconf(
        &mut self,
        conf: &crate::conf::Conf,
        section: &str,
        req: Option<&Req>,
    ) -> bool {
        let Some(s) = cstring(section) else {
            return false;
        };
        // SAFETY: all are live or NULL.
        unsafe {
            ffi::X509V3_EXT_REQ_add_nconf(
                conf.as_ptr(),
                self.as_ptr(),
                s.as_ptr(),
                req.map_or(core::ptr::null_mut(), Req::as_ptr),
            ) == 1
        }
    }

    /// `X509V3_EXT_CRL_add_nconf(conf, ctx, section, crl)`.
    pub fn crl_add_nconf(
        &mut self,
        conf: &crate::conf::Conf,
        section: &str,
        crl: Option<&Crl>,
    ) -> bool {
        let Some(s) = cstring(section) else {
            return false;
        };
        // SAFETY: all are live or NULL.
        unsafe {
            ffi::X509V3_EXT_CRL_add_nconf(
                conf.as_ptr(),
                self.as_ptr(),
                s.as_ptr(),
                crl.map_or(core::ptr::null_mut(), Crl::as_ptr),
            ) == 1
        }
    }
}

/// `BN_print(out, bn)` (NULL allowed, as `BN_print` of NULL fails).
pub fn bn_print(out: &Bio, bn: Option<&Bn>) -> c_int {
    // SAFETY: the BIO is live; the BIGNUM live or NULL.
    unsafe {
        ffi::BN_print(
            out.as_ptr(),
            bn.map_or(core::ptr::null(), |b| b.as_ptr().cast_const()),
        )
    }
}

impl Integer {
    /// `a2i_ASN1_INTEGER(bio, ai, buf, 1024)` into a new integer.
    pub fn read_a2i(bio: &Bio) -> Option<Self> {
        let ai = Self::new()?;
        let mut buf = [0 as core::ffi::c_char; 1024];
        // SAFETY: both are live; buf is writable for its length.
        let ok =
            unsafe { ffi::a2i_ASN1_INTEGER(bio.as_ptr(), ai.as_ptr(), buf.as_mut_ptr(), 1024) };
        (ok == 1).then_some(ai)
    }
}

impl Req {
    /// `X509_REQ_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = opt_cstring(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; pq NULL or a valid C string.
        Self::from_ptr(unsafe { ffi::X509_REQ_new_ex(ctx, opt_ptr(&pq)) })
    }

    /// `X509_REQ_set_version`.
    pub fn set_version(&self, v: c_long) -> bool {
        // SAFETY: the request is live.
        unsafe { ffi::X509_REQ_set_version(self.as_ptr(), v) == 1 }
    }

    /// `X509_REQ_set_subject_name`.
    pub fn set_subject_name(&self, nm: NameRef<'_>) -> bool {
        // SAFETY: both are live; the request copies the name.
        unsafe { ffi::X509_REQ_set_subject_name(self.as_ptr(), nm.0) == 1 }
    }

    /// `X509_REQ_set_pubkey` (NULL allowed, which fails).
    pub fn set_pubkey(&self, pkey: Option<&Pkey>) -> bool {
        // SAFETY: the request is live; the key live or NULL.
        unsafe {
            ffi::X509_REQ_set_pubkey(
                self.as_ptr(),
                pkey.map_or(core::ptr::null_mut(), Pkey::as_ptr),
            ) == 1
        }
    }

    /// `X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(req), type, chtype, value, -1,
    /// -1, set)`.
    pub fn add_subject_entry_by_txt(
        &self,
        field: &str,
        chtype: c_int,
        value: &str,
        set: c_int,
    ) -> bool {
        let (Some(f), Some(v)) = (cstring(field), cstring(value)) else {
            return false;
        };
        // SAFETY: the request is live; its name is owned by it.
        let nm = unsafe { ffi::X509_REQ_get_subject_name(self.as_ptr()) };
        // SAFETY: nm is live; the strings are valid and NUL-terminated (length -1).
        unsafe {
            ffi::X509_NAME_add_entry_by_txt(nm, f.as_ptr(), chtype, v.as_ptr().cast(), -1, -1, set)
                == 1
        }
    }

    /// `X509_NAME_add_entry_by_NID(X509_REQ_get_subject_name(req), nid, chtype, value, -1,
    /// -1, set)`.
    pub fn add_subject_entry_by_nid(
        &self,
        nid: c_int,
        chtype: c_int,
        value: &[u8],
        set: c_int,
    ) -> bool {
        let Ok(len) = c_int::try_from(value.len()) else {
            return false;
        };
        // SAFETY: the request is live; its name is owned by it.
        let nm = unsafe { ffi::X509_REQ_get_subject_name(self.as_ptr()) };
        // SAFETY: nm is live; value is valid for len bytes.
        unsafe {
            ffi::X509_NAME_add_entry_by_NID(nm, nid, chtype, value.as_ptr(), len, -1, set) == 1
        }
    }

    /// `X509_REQ_add1_attr_by_txt(req, name, chtype, value, -1)`.
    pub fn add1_attr_by_txt(&self, name: &str, chtype: c_int, value: &str) -> bool {
        let (Some(n), Some(v)) = (cstring(name), cstring(value)) else {
            return false;
        };
        // SAFETY: the request is live; the strings are valid (length -1: strlen).
        unsafe {
            ffi::X509_REQ_add1_attr_by_txt(self.as_ptr(), n.as_ptr(), chtype, v.as_ptr().cast(), -1)
                == 1
        }
    }

    /// `X509_REQ_add1_attr_by_NID(req, nid, chtype, value, len)`.
    pub fn add1_attr_by_nid(&self, nid: c_int, chtype: c_int, value: &[u8]) -> bool {
        let Ok(len) = c_int::try_from(value.len()) else {
            return false;
        };
        // SAFETY: the request is live; value is valid for len bytes.
        unsafe {
            ffi::X509_REQ_add1_attr_by_NID(self.as_ptr(), nid, chtype, value.as_ptr(), len) == 1
        }
    }

    /// `PEM_write_bio_X509_REQ_NEW`.
    pub fn write_pem_new(&self, bio: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_X509_REQ_NEW(bio.as_ptr(), self.as_ptr()) }
    }
}

impl Cert {
    /// `X509_add1_ext_i2d(x, nid, NULL, crit, 0)`: a NULL-valued extension (the CT poison).
    pub fn add1_ext_null(&self, nid: c_int, crit: c_int) -> c_int {
        // SAFETY: the certificate is live; a NULL value is the poison's.
        unsafe { ffi::X509_add1_ext_i2d(self.as_ptr(), nid, core::ptr::null_mut(), crit, 0) }
    }
}

/// `OBJ_create_objects(bio)`.
pub fn obj_create_objects(bio: &Bio) -> c_int {
    // SAFETY: the BIO is live.
    unsafe { ffi::OBJ_create_objects(bio.as_ptr()) }
}

/// `ASN1_STRING_set_default_mask_asc(p)`.
pub fn set_default_mask_asc(p: &str) -> bool {
    let Some(c) = cstring(p) else {
        return false;
    };
    // SAFETY: a valid C string.
    unsafe { ffi::ASN1_STRING_set_default_mask_asc(c.as_ptr()) == 1 }
}

// ---- `ca`: CRLs, revoked entries, name entries, and times.

crate::handle!(
    /// An owned `X509_REVOKED`.
    Revoked, X509_REVOKED, X509_REVOKED_free
);

impl Revoked {
    /// `X509_REVOKED_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_REVOKED_new() })
    }

    /// `X509_REVOKED_set_revocationDate` (copied).
    pub fn set_revocation_date(&self, t: &Time) -> bool {
        // SAFETY: both are live; the entry copies the time.
        unsafe { ffi::X509_REVOKED_set_revocationDate(self.as_ptr(), t.as_ptr()) == 1 }
    }

    /// `X509_REVOKED_set_serialNumber` (copied).
    pub fn set_serial(&self, sn: &Integer) -> bool {
        // SAFETY: both are live; the entry copies the serial.
        unsafe { ffi::X509_REVOKED_set_serialNumber(self.as_ptr(), sn.as_ptr()) == 1 }
    }

    /// `X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, ASN1_ENUMERATED(code), 0, 0)`.
    pub fn add_reason(&self, nid: c_int, code: c_long) -> c_int {
        // SAFETY: no arguments.
        let e = unsafe { ffi::ASN1_ENUMERATED_new() };
        if e.is_null() {
            return 0;
        }
        // SAFETY: e is live.
        let mut r = if unsafe { ffi::ASN1_ENUMERATED_set(e, code) } == 1 {
            1
        } else {
            0
        };
        if r == 1 {
            // SAFETY: both are live; the entry encodes a copy.
            r = unsafe { ffi::X509_REVOKED_add1_ext_i2d(self.as_ptr(), nid, e.cast(), 0, 0) };
        }
        // SAFETY: e is owned here.
        unsafe { ffi::ASN1_ENUMERATED_free(e) };
        r
    }

    /// `X509_REVOKED_add1_ext_i2d(rev, nid, time, 0, 0)` (an `ASN1_GENERALIZEDTIME`).
    pub fn add_time_ext(&self, nid: c_int, t: &Time) -> c_int {
        // SAFETY: both are live; the entry encodes a copy.
        unsafe { ffi::X509_REVOKED_add1_ext_i2d(self.as_ptr(), nid, t.as_ptr().cast(), 0, 0) }
    }

    /// `X509_REVOKED_add1_ext_i2d(rev, nid, obj, 0, 0)` (an `ASN1_OBJECT`).
    pub fn add_obj_ext(&self, nid: c_int, obj: &Obj) -> c_int {
        // SAFETY: both are live; the entry encodes a copy.
        unsafe { ffi::X509_REVOKED_add1_ext_i2d(self.as_ptr(), nid, obj.as_ptr().cast(), 0, 0) }
    }
}

impl Crl {
    /// `X509_CRL_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = opt_cstring(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx NULL or live; pq NULL or a valid C string.
        Self::from_ptr(unsafe { ffi::X509_CRL_new_ex(ctx, opt_ptr(&pq)) })
    }

    /// `X509_CRL_set_issuer_name`.
    pub fn set_issuer_name(&self, nm: NameRef<'_>) -> bool {
        // SAFETY: both are live; the CRL copies the name.
        unsafe { ffi::X509_CRL_set_issuer_name(self.as_ptr(), nm.0) == 1 }
    }

    /// `X509_CRL_set1_lastUpdate`.
    pub fn set1_last_update(&self, t: &Time) -> bool {
        // SAFETY: both are live; the CRL copies the time.
        unsafe { ffi::X509_CRL_set1_lastUpdate(self.as_ptr(), t.as_ptr()) == 1 }
    }

    /// `X509_CRL_set1_nextUpdate`.
    pub fn set1_next_update(&self, t: &Time) -> bool {
        // SAFETY: as above.
        unsafe { ffi::X509_CRL_set1_nextUpdate(self.as_ptr(), t.as_ptr()) == 1 }
    }

    /// `X509_CRL_add0_revoked` (the CRL takes the entry).
    pub fn add0_revoked(&self, r: Revoked) -> bool {
        // SAFETY: both are live; the CRL takes r.
        unsafe { ffi::X509_CRL_add0_revoked(self.as_ptr(), r.into_ptr()) == 1 }
    }

    /// `X509_CRL_sort`.
    pub fn sort(&self) -> bool {
        // SAFETY: the CRL is live.
        unsafe { ffi::X509_CRL_sort(self.as_ptr()) == 1 }
    }

    /// `X509_CRL_add1_ext_i2d(crl, nid, integer, crit, flags)`.
    pub fn add1_ext_integer(&self, nid: c_int, v: &Integer, crit: c_int, flags: c_ulong) -> c_int {
        // SAFETY: both are live; the CRL encodes a copy.
        unsafe { ffi::X509_CRL_add1_ext_i2d(self.as_ptr(), nid, v.as_ptr().cast(), crit, flags) }
    }

    /// `X509_CRL_set_version`.
    pub fn set_version(&self, v: c_long) -> bool {
        // SAFETY: the CRL is live.
        unsafe { ffi::X509_CRL_set_version(self.as_ptr(), v) == 1 }
    }
}

impl Time {
    /// `ASN1_UTCTIME_new` then `ASN1_UTCTIME_set_string(t, s)`: `None` if `s` isn't one.
    pub fn utc_from_string(s: &str) -> Result<Self, bool> {
        let c = cstring(s).ok_or(false)?;
        // SAFETY: no arguments.
        let t = Self::from_ptr(unsafe { ffi::ASN1_UTCTIME_new() }).ok_or(true)?;
        // SAFETY: t is live; c a valid C string.
        if unsafe { ffi::ASN1_UTCTIME_set_string(t.as_ptr(), c.as_ptr()) } == 1 {
            Ok(t)
        } else {
            Err(false)
        }
    }

    /// `ASN1_GENERALIZEDTIME_new` then `ASN1_GENERALIZEDTIME_set_string(t, s)`.
    pub fn generalized_from_string(s: &str) -> Result<Self, bool> {
        let c = cstring(s).ok_or(false)?;
        // SAFETY: no arguments.
        let t = Self::from_ptr(unsafe { ffi::ASN1_GENERALIZEDTIME_new() }).ok_or(true)?;
        // SAFETY: t is live; c a valid C string.
        if unsafe { ffi::ASN1_GENERALIZEDTIME_set_string(t.as_ptr(), c.as_ptr()) } == 1 {
            Ok(t)
        } else {
            Err(false)
        }
    }

    /// `X509_gmtime_adj(NULL, 0)`: now, as a new time.
    pub fn now_utc() -> Option<Self> {
        // SAFETY: NULL asks for a new time.
        Self::from_ptr(unsafe { ffi::X509_gmtime_adj(core::ptr::null_mut(), 0) })
    }

    /// `X509_time_adj(t, 0, NULL)`: sets `t` to now.
    pub fn set_now(&self) -> bool {
        // SAFETY: the time is live; NULL means now.
        !unsafe { ffi::X509_time_adj(self.as_ptr(), 0, core::ptr::null_mut()) }.is_null()
    }

    /// `X509_gmtime_adj(t, 0)` (`true`) or `X509_time_adj_ex(t, days, secs, NULL)`.
    pub fn set_adj(&self, days: c_int, secs: c_long) -> bool {
        // SAFETY: the time is live; NULL means now.
        !unsafe { ffi::X509_time_adj_ex(self.as_ptr(), days, secs, core::ptr::null_mut()) }
            .is_null()
    }
}

/// `ASN1_TIME_set_string(NULL, s)`: whether `s` is a valid time.
pub fn time_set_string_check(s: &str) -> bool {
    let Some(c) = cstring(s) else {
        return false;
    };
    // SAFETY: NULL only checks the string.
    unsafe { ffi::ASN1_TIME_set_string(core::ptr::null_mut(), c.as_ptr()) == 1 }
}

/// `ASN1_GENERALIZEDTIME_set_string(NULL, s)`: whether `s` is a valid time.
pub fn generalized_time_check(s: &str) -> bool {
    let Some(c) = cstring(s) else {
        return false;
    };
    // SAFETY: NULL only checks the string.
    unsafe { ffi::ASN1_GENERALIZEDTIME_set_string(core::ptr::null_mut(), c.as_ptr()) == 1 }
}

/// `ASN1_TIME_diff(&pday, NULL, NULL, to)`: the days from now to `to`.
pub fn days_until(to: TimeRef<'_>) -> Option<c_int> {
    let mut d: c_int = 0;
    // SAFETY: d is a valid out-pointer; NULL from means now; to is live.
    (unsafe { ffi::ASN1_TIME_diff(&mut d, core::ptr::null_mut(), core::ptr::null(), to.0) } == 1)
        .then_some(d)
}

/// An `X509_NAME_ENTRY` borrowed from its name.
#[derive(Clone, Copy)]
pub struct NameEntryRef<'a>(
    *mut crate::abi::X509_NAME_ENTRY,
    core::marker::PhantomData<&'a ()>,
);

impl NameEntryRef<'_> {
    fn obj(self) -> *mut crate::abi::ASN1_OBJECT {
        // SAFETY: the entry is live; the object is owned by it.
        unsafe { ffi::X509_NAME_ENTRY_get_object(self.0) }
    }

    fn data_ptr(self) -> *mut crate::abi::ASN1_STRING {
        // SAFETY: the entry is live; the string is owned by it.
        unsafe { ffi::X509_NAME_ENTRY_get_data(self.0) }
    }

    /// `OBJ_obj2nid` of its object.
    pub fn nid(self) -> c_int {
        // SAFETY: the object is live.
        unsafe { ffi::OBJ_obj2nid(self.obj()) }
    }

    /// Its value's type (`str->type`).
    pub fn data_type(self) -> c_int {
        let s = self.data_ptr();
        if s.is_null() {
            return 0;
        }
        // SAFETY: s is a live ASN1_STRING (public layout).
        unsafe { (*s).type_ }
    }

    /// Its value's bytes.
    pub fn data(self) -> Vec<u8> {
        asn1_string_bytes(self.data_ptr())
    }

    /// Sets its value's type in place (`str->type = t`, as `ca -msie_hack` does).
    pub fn set_data_type(self, t: c_int) {
        let s = self.data_ptr();
        if !s.is_null() {
            // SAFETY: s is a live ASN1_STRING owned by the entry, which upstream changes in
            // place too.
            unsafe { (*s).type_ = t };
        }
    }

    /// `ASN1_UNIVERSALSTRING_to_string` on its value, in place.
    pub fn universal_to_string(self) {
        // SAFETY: the value is live; the call converts it in place.
        unsafe { ffi::ASN1_UNIVERSALSTRING_to_string(self.data_ptr()) };
    }

    /// `i2a_ASN1_OBJECT(out, obj)` of its object: what it returns.
    pub fn print_obj(self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2a_ASN1_OBJECT(out.as_ptr(), self.obj()) }
    }

    /// `ASN1_STRING_cmp` of the two values.
    pub fn data_cmp(self, other: NameEntryRef<'_>) -> c_int {
        // SAFETY: both strings are live.
        unsafe { ffi::ASN1_STRING_cmp(self.data_ptr(), other.data_ptr()) }
    }
}

impl<'a> NameRef<'a> {
    /// `X509_NAME_get_entry(nm, i)`.
    pub fn entry(self, i: c_int) -> Option<NameEntryRef<'a>> {
        // SAFETY: the name is live; out-of-range gives NULL.
        let e = unsafe { ffi::X509_NAME_get_entry(self.0, i) };
        (!e.is_null()).then_some(NameEntryRef(e, core::marker::PhantomData))
    }

    /// `X509_NAME_get_index_by_NID(nm, nid, last)`.
    pub fn index_by_nid(self, nid: c_int, last: c_int) -> c_int {
        // SAFETY: the name is live.
        unsafe { ffi::X509_NAME_get_index_by_NID(self.0, nid, last) }
    }
}

impl Name {
    /// `X509_NAME_add_entry(nm, e, -1, 0)` (copied).
    pub fn add_entry(&self, e: NameEntryRef<'_>) -> bool {
        // SAFETY: both are live; the name copies the entry.
        unsafe { ffi::X509_NAME_add_entry(self.as_ptr(), e.0, -1, 0) == 1 }
    }

    /// `X509_NAME_ENTRY_free(X509_NAME_delete_entry(nm, i))`.
    pub fn delete_entry(&self, i: c_int) {
        // SAFETY: the name is live; the entry returned is the caller's.
        let e = unsafe { ffi::X509_NAME_delete_entry(self.as_ptr(), i) };
        // SAFETY: e is NULL or owned here.
        unsafe { ffi::X509_NAME_ENTRY_free(e) };
    }
}

/// `ASN1_PRINTABLE_type(bytes, len)`.
pub fn printable_type(bytes: &[u8]) -> c_int {
    let Ok(n) = c_int::try_from(bytes.len()) else {
        return 0;
    };
    // SAFETY: bytes is valid for n bytes.
    unsafe { ffi::ASN1_PRINTABLE_type(bytes.as_ptr(), n) }
}

impl Integer {
    /// Its content bytes (`ASN1_STRING_get0_data`).
    pub fn bytes(&self) -> Vec<u8> {
        asn1_string_bytes(self.as_ptr().cast_const().cast())
    }
}

impl Req {
    /// `X509_REQ_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_REQ_new() })
    }

    /// `X509_REQ_check_private_key`.
    pub fn check_private_key(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::X509_REQ_check_private_key(self.as_ptr(), pkey.as_ptr()) == 1 }
    }
}

impl Pkey {
    /// `EVP_PKEY_missing_parameters`.
    pub fn missing_parameters(&self) -> bool {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_missing_parameters(self.as_ptr()) != 0 }
    }

    /// `EVP_PKEY_copy_parameters(self, from)`.
    pub fn copy_parameters(&self, from: &Pkey) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::EVP_PKEY_copy_parameters(self.as_ptr(), from.as_ptr()) == 1 }
    }
}

// Printing and writing certificates and CRLs, and borrowing stack members (fork G4).

impl Cert {
    /// A new reference to a certificate the caller only borrows (`X509_up_ref`).
    pub(crate) fn from_borrowed(p: *mut crate::abi::X509) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a live certificate; the new reference is owned by the result.
        unsafe { ffi::X509_up_ref(p) };
        Self::from_ptr(p)
    }
}

impl Crl {
    /// A new reference to a CRL the caller only borrows (`X509_CRL_up_ref`).
    pub(crate) fn from_borrowed(p: *mut X509_CRL) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a live CRL; the new reference is owned by the result.
        unsafe { ffi::X509_CRL_up_ref(p) };
        Self::from_ptr(p)
    }
}

/// The certificates of a stack the caller borrows (NULL: none), each as a new reference.
pub(crate) fn certs_of(sk: *const stack_st_X509) -> Vec<Cert> {
    let mut out = Vec::new();
    if sk.is_null() {
        return out;
    }
    // SAFETY: sk is a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the member is a live X509.
        let p = unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) }.cast::<crate::abi::X509>();
        if let Some(c) = Cert::from_borrowed(p) {
            out.push(c);
        }
    }
    out
}

/// The CRLs of a stack the caller borrows (NULL: none), each as a new reference.
pub(crate) fn crls_of(sk: *const stack_st_X509_CRL) -> Vec<Crl> {
    let mut out = Vec::new();
    if sk.is_null() {
        return out;
    }
    // SAFETY: sk is a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the member is a live X509_CRL.
        let p = unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) }.cast::<X509_CRL>();
        if let Some(c) = Crl::from_borrowed(p) {
            out.push(c);
        }
    }
    out
}

impl CertStack {
    /// The certificates, each as a new reference.
    pub fn to_vec(&self) -> Vec<Cert> {
        certs_of(self.as_ptr())
    }

    /// `sk_X509_push` of a new reference to `cert`.
    pub fn push_ref(&self, cert: &Cert) -> bool {
        let Some(c) = Cert::from_borrowed(cert.as_ptr()) else {
            return false;
        };
        // SAFETY: both are live; on success the stack owns the new reference.
        if unsafe { ffi::OPENSSL_sk_push(self.as_ptr().cast(), c.as_ptr().cast()) } > 0 {
            core::mem::forget(c);
            true
        } else {
            false
        }
    }

    /// Gives up ownership.
    pub fn into_ptr(self) -> *mut stack_st_X509 {
        let p = self.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl CrlStack {
    /// The CRLs, each as a new reference.
    pub fn to_vec(&self) -> Vec<Crl> {
        crls_of(self.as_ptr())
    }
}

impl Cert {
    /// `X509_get_extension_flags`.
    pub fn extension_flags(&self) -> u32 {
        // SAFETY: the certificate is live.
        unsafe { ffi::X509_get_extension_flags(self.as_ptr()) }
    }

    /// `X509_cmp_timeframe(vpm, X509_get0_notBefore(x), X509_get0_notAfter(x))`: 0 when
    /// valid now (or at the parameters' time), positive when expired, negative when not yet
    /// valid.
    pub fn cmp_timeframe(&self, vpm: Option<&crate::verify::VerifyParam>) -> c_int {
        // SAFETY: the certificate is live; the times are owned by it.
        let nb = unsafe { ffi::X509_get0_notBefore(self.as_ptr()) };
        // SAFETY: as above.
        let na = unsafe { ffi::X509_get0_notAfter(self.as_ptr()) };
        let v = vpm.map_or(core::ptr::null(), |v| v.as_ptr().cast_const());
        // SAFETY: v is NULL or live; the times are live.
        unsafe { ffi::X509_cmp_timeframe(v, nb, na) }
    }
}

impl Cert {
    /// A new reference to the same certificate (`X509_up_ref`).
    pub fn clone_ref(&self) -> Cert {
        // SAFETY: the certificate is live; the new reference is owned by the result.
        unsafe { ffi::X509_up_ref(self.as_ptr()) };
        Cert(self.0)
    }
}

impl NameRef<'_> {
    /// The name at `p`, borrowed from its owner (NULL allowed, see [`NameRef`]).
    pub(crate) fn from_raw(p: *const X509_NAME) -> Self {
        Self::new(p)
    }

    /// The name, for the C API.
    pub(crate) fn as_raw(self) -> *const X509_NAME {
        self.0
    }
}
