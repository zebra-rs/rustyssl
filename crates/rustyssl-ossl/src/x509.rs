//! Certificates, CRLs, requests, names, stacks of them, and extensions.

use core::ffi::{c_int, c_long, c_ulong, c_void};

use crate::abi::{
    ASN1_OCTET_STRING, CONF_VALUE, OPENSSL_STACK, X509_CRL, X509_EXTENSION, X509_NAME, X509V3_CTX,
    stack_st_X509, stack_st_X509_CRL,
};
use crate::bio::Bio;
use crate::ffi;
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
    fn new(p: *const X509_NAME) -> Self {
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

    /// `PEM_write_bio_X509`.
    pub fn write_pem(&self, bio: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_X509(bio.as_ptr(), self.as_ptr()) == 1 }
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
