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

crate::handle!(
    /// An owned `PKCS7`.
    Pkcs7, PKCS7, PKCS7_free
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

impl CertRef<'_> {
    pub fn as_ptr(self) -> *mut crate::abi::X509 {
        self.0
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
    pub fn from_bn(bn: &crate::x509::Bn) -> Option<Self> {
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

crate::handle!(
    /// An owned `BIGNUM`.
    Bn, BIGNUM, BN_free
);

impl Bn {
    /// `BN_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::BN_new() })
    }

    /// `BN_hex2bn`: the BIGNUM, and how many characters it used (0 on failure).
    pub fn from_hex(s: &str) -> (Option<Self>, c_int) {
        let Some(c) = cstring(s) else {
            return (None, 0);
        };
        let mut p: *mut crate::abi::BIGNUM = core::ptr::null_mut();
        // SAFETY: p is a valid out-pointer; c a valid C string.
        let n = unsafe { ffi::BN_hex2bn(&mut p, c.as_ptr()) };
        (Self::from_ptr(p), n)
    }

    /// `BN_bn2hex`.
    pub fn to_hex(&self) -> Option<String> {
        // SAFETY: the BIGNUM is live; the string is the caller's to free.
        take_string(unsafe { ffi::BN_bn2hex(self.as_ptr()) })
    }

    /// `BN_add_word`.
    pub fn add_word(&self, w: c_ulong) -> bool {
        // SAFETY: the BIGNUM is live.
        unsafe { ffi::BN_add_word(self.as_ptr(), w) == 1 }
    }

    /// `BN_is_zero`.
    pub fn is_zero(&self) -> bool {
        // SAFETY: the BIGNUM is live.
        unsafe { ffi::BN_is_zero(self.as_ptr()) == 1 }
    }

    /// `BN_rand(bn, bits, top, bottom)`.
    pub fn rand(&self, bits: c_int, top: c_int, bottom: c_int) -> bool {
        // SAFETY: the BIGNUM is live.
        unsafe { ffi::BN_rand(self.as_ptr(), bits, top, bottom) == 1 }
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
