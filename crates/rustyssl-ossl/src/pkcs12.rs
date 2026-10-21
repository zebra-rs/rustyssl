//! PKCS#12 (`PKCS12`, its safe bags, MACs, and the algorithms `pkcs12 -info` prints).

use core::ffi::{c_char, c_int, c_long, c_void};
use std::ffi::CString;

use crate::abi::{
    ASN1_TYPE, NID_hmacWithSHA1, NID_id_pbkdf2, NID_id_scrypt, NID_oracle_jdk_trustedkeyusage,
    NID_pbes2, PBE2PARAM, PBEPARAM, PBKDF2PARAM, PKCS12_SAFEBAG, SCRYPT_PARAMS, V_ASN1_OBJECT,
    V_ASN1_SEQUENCE, X509_ALGOR, stack_st_PKCS12_SAFEBAG,
};
use crate::bio::Bio;
use crate::evp::{Cipher, Md};
use crate::ffi;
use crate::object::{
    Attribute, Object, Value, attributes_of, integer_get, value_of, with_unpacked,
};
use crate::pkcs7::Pkcs7;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::{cstring, openssl_free};
use crate::x509::{Cert, CertStack, Store};

crate::handle!(
    /// An owned `PKCS12`.
    Pkcs12, PKCS12, PKCS12_free
);

/// An optional C string argument: `Err` if it holds a NUL.
fn opt_c(s: Option<&[u8]>) -> Result<Option<CString>, ()> {
    s.map(|b| CString::new(b).map_err(|_| ())).transpose()
}

fn ptr_of(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

fn opt_propq(propq: Option<&str>) -> Result<Option<CString>, ()> {
    opt_c(propq.map(str::as_bytes))
}

fn ctx_ptr(libctx: Option<&LibCtx>) -> *mut crate::abi::OSSL_LIB_CTX {
    libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr)
}

/// The details of a MAC (`pkcs12 -info`).
pub struct MacInfo {
    /// The MAC algorithm.
    pub alg: Option<Object>,
    /// For PBMAC1: the PBKDF2 parameters (iteration count, key length, salt length, PRF),
    /// `None` if they are unsupported.
    pub pbmac1: Option<(c_long, c_long, c_int, c_int)>,
    pub iter: Option<c_long>,
    pub mac_len: c_int,
    pub salt_len: c_int,
}

/// `PKCS12_create_ex2`'s `jdk_trust` callback of `pkcs12.c`: adds the JDK trusted-usage
/// attribute naming the object `cbarg` (NULL: nothing to do).
unsafe extern "C" fn jdk_trust(bag: *mut PKCS12_SAFEBAG, cbarg: *mut c_void) -> c_int {
    if cbarg.is_null() {
        return 1;
    }
    // SAFETY: bag is the live bag being created; cbarg is the ASN1_OBJECT passed by
    // create_ex2, alive for the call. The attribute stack is reused as upstream does.
    let mut attrs = unsafe { ffi::PKCS12_SAFEBAG_get0_attrs(bag) }.cast_mut();
    // SAFETY: as above.
    let attr =
        unsafe { ffi::X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT, cbarg) };
    // SAFETY: attrs is NULL or the bag's stack; attr NULL or live.
    unsafe { ffi::X509at_add1_attr(&mut attrs, attr) };
    // SAFETY: the bag takes the stack (the one it had, or the one just made).
    unsafe { ffi::PKCS12_SAFEBAG_set0_attrs(bag, attrs) };
    // SAFETY: attr is owned here (the stack holds a copy).
    unsafe { ffi::X509_ATTRIBUTE_free(attr) };
    1
}

impl Pkcs12 {
    /// `PKCS12_init_ex(mode, libctx, propq)`.
    pub fn init_ex(mode: c_int, libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = opt_propq(propq).ok()?;
        // SAFETY: libctx is NULL or live; pq NULL or a valid C string.
        Self::from_ptr(unsafe { ffi::PKCS12_init_ex(mode, ctx_ptr(libctx), ptr_of(&pq)) })
    }

    /// `d2i_PKCS12_bio(bio, &self)`: the object filled in, or `None`.
    pub fn read_der_into(self, bio: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: the BIO is live; p is an object the call may reuse or free.
        let r = unsafe { ffi::d2i_PKCS12_bio(bio.as_ptr(), &mut p) };
        if r.is_null() {
            // SAFETY: what is left in p (NULL or the object) is still owned here.
            unsafe { ffi::PKCS12_free(p) };
            return None;
        }
        Self::from_ptr(r)
    }

    /// `d2i_PKCS12_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_PKCS12_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `i2d_PKCS12_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PKCS12_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `PKCS12_create_ex2(pass, name, key, cert, ca, nid_key, nid_cert, iter, -1, keytype,
    /// libctx, propq, jdk_trust, obj)`, the object being `jdk_trust`'s (`OBJ_txt2obj(.., 0)`).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        pass: Option<&[u8]>,
        name: Option<&str>,
        key: Option<&Pkey>,
        cert: Option<&Cert>,
        ca: Option<&CertStack>,
        nid_key: c_int,
        nid_cert: c_int,
        iter: c_int,
        keytype: c_int,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        jdk: Option<&Object>,
    ) -> Option<Self> {
        let pass = opt_c(pass).ok()?;
        let name = opt_c(name.map(str::as_bytes)).ok()?;
        let pq = opt_propq(propq).ok()?;
        // SAFETY: every pointer is NULL or live for the call; the callback gets the object
        // (or NULL), which outlives the call.
        Self::from_ptr(unsafe {
            ffi::PKCS12_create_ex2(
                ptr_of(&pass),
                ptr_of(&name),
                key.map_or(core::ptr::null_mut(), Pkey::as_ptr),
                cert.map_or(core::ptr::null_mut(), Cert::as_ptr),
                ca.map_or(core::ptr::null_mut(), CertStack::as_ptr),
                nid_key,
                nid_cert,
                iter,
                -1,
                keytype,
                ctx_ptr(libctx),
                ptr_of(&pq),
                Some(jdk_trust),
                jdk.map_or(core::ptr::null_mut(), |o| o.as_ptr().cast()),
            )
        })
    }

    /// `PKCS12_set_mac(p12, pass, -1, NULL, saltlen, iter, md)`.
    pub fn set_mac(
        &self,
        pass: Option<&[u8]>,
        saltlen: c_int,
        iter: c_int,
        md: Option<&Md>,
    ) -> bool {
        let Ok(pass) = opt_c(pass) else {
            return false;
        };
        // SAFETY: the object is live; pass NULL or a C string; md NULL or live.
        unsafe {
            ffi::PKCS12_set_mac(
                self.as_ptr(),
                ptr_of(&pass),
                -1,
                core::ptr::null_mut(),
                saltlen,
                iter,
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
            ) == 1
        }
    }

    /// `PKCS12_set_pbmac1_pbkdf2(p12, pass, -1, NULL, saltlen, iter, md, prf_md_name)`.
    pub fn set_pbmac1_pbkdf2(
        &self,
        pass: Option<&[u8]>,
        saltlen: c_int,
        iter: c_int,
        md: Option<&Md>,
        prf_md_name: Option<&str>,
    ) -> bool {
        let (Ok(pass), Ok(prf)) = (opt_c(pass), opt_c(prf_md_name.map(str::as_bytes))) else {
            return false;
        };
        // SAFETY: as above.
        unsafe {
            ffi::PKCS12_set_pbmac1_pbkdf2(
                self.as_ptr(),
                ptr_of(&pass),
                -1,
                core::ptr::null_mut(),
                saltlen,
                iter,
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
                ptr_of(&prf),
            ) == 1
        }
    }

    /// `PKCS12_mac_present`.
    pub fn mac_present(&self) -> bool {
        // SAFETY: the object is live.
        unsafe { ffi::PKCS12_mac_present(self.as_ptr()) == 1 }
    }

    /// The MAC's algorithm (`PKCS12_get0_mac`'s `macalgid`), `None` when there is no MAC.
    pub fn mac_alg(&self) -> Option<Option<Object>> {
        let mut alg: *const X509_ALGOR = core::ptr::null();
        // SAFETY: the object is live; the other outputs are not wanted (NULL).
        unsafe {
            ffi::PKCS12_get0_mac(
                core::ptr::null_mut(),
                &mut alg,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                self.as_ptr(),
            )
        };
        if alg.is_null() {
            return None;
        }
        Some(algor_object(alg))
    }

    /// The MAC's details, for `-info`.
    pub fn mac_info(&self) -> MacInfo {
        let mut mac = core::ptr::null();
        let mut alg: *const X509_ALGOR = core::ptr::null();
        let mut salt = core::ptr::null();
        let mut iter = core::ptr::null();
        // SAFETY: the object is live; the outputs are borrowed from it.
        unsafe { ffi::PKCS12_get0_mac(&mut mac, &mut alg, &mut salt, &mut iter, self.as_ptr()) };
        let obj = algor_object(alg);
        let pbmac1 = if obj
            .as_ref()
            .is_some_and(|o| o.nid() == crate::abi::NID_pbmac1)
        {
            // SAFETY: alg is the MAC's live algorithm; the result is owned here.
            let p = unsafe { ffi::PBMAC1_get1_pbkdf2_param(alg) };
            let r = (!p.is_null()).then(|| {
                // SAFETY: p is a live PBKDF2PARAM, its fields NULL or live.
                unsafe { pbkdf2_details(p) }
            });
            // SAFETY: p is owned here.
            unsafe { ffi::PBKDF2PARAM_free(p) };
            r
        } else {
            None
        };
        let len = |s: *const crate::abi::ASN1_OCTET_STRING| {
            if s.is_null() {
                0
            } else {
                // SAFETY: the string is live (borrowed from the object).
                unsafe { ffi::ASN1_STRING_length(s) }
            }
        };
        MacInfo {
            alg: obj,
            pbmac1,
            iter: (!iter.is_null()).then(|| integer_get(iter)),
            mac_len: len(mac),
            salt_len: len(salt),
        }
    }

    /// `PKCS12_verify_mac(p12, pass, -1)`, or `(p12, NULL, 0)` for `None`.
    pub fn verify_mac(&self, pass: Option<&[u8]>) -> bool {
        let Ok(c) = opt_c(pass) else {
            return false;
        };
        let len = if c.is_some() { -1 } else { 0 };
        // SAFETY: the object is live; c NULL or a C string.
        unsafe { ffi::PKCS12_verify_mac(self.as_ptr(), ptr_of(&c), len) == 1 }
    }

    /// `PKCS12_unpack_authsafes`: the PKCS#7 objects, `None` if it fails.
    pub fn authsafes(&self) -> Option<Vec<Pkcs7>> {
        // SAFETY: the object is live; the stack and its members are the caller's.
        let sk = unsafe { ffi::PKCS12_unpack_authsafes(self.as_ptr()) };
        if sk.is_null() {
            return None;
        }
        let mut out = Vec::new();
        // SAFETY: sk is live.
        let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each member is now owned by `out`.
            let p = unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) };
            if let Some(p7) = Pkcs7::from_raw(p.cast()) {
                out.push(p7);
            }
        }
        // SAFETY: only the stack itself is freed; its members are owned by `out`.
        unsafe { ffi::OPENSSL_sk_free(sk.cast()) };
        Some(out)
    }
}

/// `OPENSSL_asc2uni` then `OPENSSL_uni2utf8` of a password: `Err(true)` if the first fails,
/// `Err(false)` if the second does.
pub fn asc2uni_utf8(pass: &[u8]) -> Result<Vec<u8>, bool> {
    let c = CString::new(pass).map_err(|_| true)?;
    let mut len: c_int = 0;
    // SAFETY: c is a C string; the result is the caller's to free.
    let u = unsafe { ffi::OPENSSL_asc2uni(c.as_ptr(), -1, core::ptr::null_mut(), &mut len) };
    if u.is_null() {
        return Err(true);
    }
    // SAFETY: u holds len bytes; the result is the caller's to free.
    let s = unsafe { ffi::OPENSSL_uni2utf8(u, len) };
    openssl_free(u.cast());
    if s.is_null() {
        return Err(false);
    }
    // SAFETY: s is a NUL-terminated string.
    let v = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes().to_vec();
    openssl_free(s.cast());
    Ok(v)
}

/// The algorithm object of an `X509_ALGOR` the caller borrows.
fn algor_object(alg: *const X509_ALGOR) -> Option<Object> {
    if alg.is_null() {
        return None;
    }
    let mut obj = core::ptr::null();
    // SAFETY: alg is live; only the object is wanted.
    unsafe { ffi::X509_ALGOR_get0(&mut obj, core::ptr::null_mut(), core::ptr::null_mut(), alg) };
    Object::dup_from(obj)
}

/// An algorithm's object, parameter type, and parameter.
fn algor_get0(alg: *const X509_ALGOR) -> (c_int, c_int, *const c_void) {
    let mut obj = core::ptr::null();
    let mut ptype: c_int = 0;
    let mut pval = core::ptr::null();
    if !alg.is_null() {
        // SAFETY: alg is live; the outputs are borrowed from it.
        unsafe { ffi::X509_ALGOR_get0(&mut obj, &mut ptype, &mut pval, alg) };
    }
    // SAFETY: obj is NULL or live (NID_undef for NULL).
    (unsafe { ffi::OBJ_obj2nid(obj) }, ptype, pval)
}

/// PBKDF2's iteration count, key length, salt length, and PRF.
///
/// # Safety
/// `p`'s fields are NULL or live.
unsafe fn pbkdf2_details(p: *const PBKDF2PARAM) -> (c_long, c_long, c_int, c_int) {
    // SAFETY: the caller's guarantee.
    let p = unsafe { &*p };
    let prf = if p.prf.is_null() {
        NID_hmacWithSHA1
    } else {
        algor_get0(p.prf).0
    };
    let salt_len = if p.salt.is_null() {
        0
    } else {
        // SAFETY: salt is a live ASN1_TYPE; its value is read as the octet string upstream
        // reads it (a pointer member).
        let t = unsafe { *p.salt };
        // SAFETY: as above.
        let o = unsafe { t.value.octet_string };
        // SAFETY: o is NULL or a live string.
        unsafe { ffi::ASN1_STRING_length(o) }
    };
    (integer_get(p.iter), integer_get(p.keylength), salt_len, prf)
}

/// A key derivation's parameters (`alg_print`).
pub enum Kdf {
    /// PBKDF2: iteration count and PRF, `None` for unsupported parameters.
    Pbkdf2(Option<(c_long, c_int)>),
    /// scrypt: salt length, N, r, p.
    Scrypt(Option<(c_int, c_long, c_long, c_long)>),
    Other,
}

/// A PBE algorithm's parameters (`alg_print`).
pub enum AlgDetail {
    /// PBES2: the KDF's NID, the cipher's NID, and the KDF's parameters; `None` for
    /// unsupported parameters.
    Pbes2(Option<(c_int, c_int, Kdf)>),
    /// A PKCS#5 v1.5 or PKCS#12 PBE: its iteration count, `None` for unsupported parameters.
    Pbe(Option<c_long>),
}

/// An algorithm's NID and parameters.
pub struct AlgInfo {
    pub nid: c_int,
    pub detail: AlgDetail,
}

/// The sequence parameter of an algorithm, as the string `ASN1_item_unpack` takes.
fn seq_param(ptype: c_int, pval: *const c_void) -> *const crate::abi::ASN1_STRING {
    if ptype == V_ASN1_SEQUENCE {
        pval.cast()
    } else {
        core::ptr::null()
    }
}

/// `alg_print`'s view of an algorithm the caller borrows.
pub(crate) fn alg_info(alg: *const X509_ALGOR) -> AlgInfo {
    let (nid, ptype, pval) = algor_get0(alg);
    if nid == NID_pbes2 {
        // SAFETY: the item functions take no arguments.
        let it = unsafe { ffi::PBE2PARAM_it() };
        let detail = with_unpacked(seq_param(ptype, pval), it, |p| {
            // SAFETY: p is a live PBE2PARAM.
            let pbe2 = unsafe { &*p.cast::<PBE2PARAM>() };
            let (kdf_nid, kptype, kpval) = algor_get0(pbe2.keyfunc);
            let enc_nid = algor_get0(pbe2.encryption).0;
            let kdf = if kdf_nid == NID_id_pbkdf2 {
                // SAFETY: as above.
                let it = unsafe { ffi::PBKDF2PARAM_it() };
                Kdf::Pbkdf2(with_unpacked(seq_param(kptype, kpval), it, |k| {
                    // SAFETY: k is a live PBKDF2PARAM.
                    let k = unsafe { pbkdf2_details(k.cast::<PBKDF2PARAM>()) };
                    (k.0, k.3)
                }))
            } else if kdf_nid == NID_id_scrypt {
                // SAFETY: as above.
                let it = unsafe { ffi::SCRYPT_PARAMS_it() };
                Kdf::Scrypt(with_unpacked(seq_param(kptype, kpval), it, |k| {
                    // SAFETY: k is a live SCRYPT_PARAMS, its fields NULL or live.
                    let k = unsafe { &*k.cast::<SCRYPT_PARAMS>() };
                    // SAFETY: the salt is NULL or live.
                    let salt = unsafe { ffi::ASN1_STRING_length(k.salt) };
                    (
                        salt,
                        integer_get(k.costParameter),
                        integer_get(k.blockSize),
                        integer_get(k.parallelizationParameter),
                    )
                }))
            } else {
                Kdf::Other
            };
            (kdf_nid, enc_nid, kdf)
        });
        AlgInfo {
            nid,
            detail: AlgDetail::Pbes2(detail),
        }
    } else {
        // SAFETY: as above.
        let it = unsafe { ffi::PBEPARAM_it() };
        let iter = with_unpacked(seq_param(ptype, pval), it, |p| {
            // SAFETY: p is a live PBEPARAM.
            integer_get(unsafe { (*p.cast::<PBEPARAM>()).iter })
        });
        AlgInfo {
            nid,
            detail: AlgDetail::Pbe(iter),
        }
    }
}

/// The algorithm of an encrypted PKCS#7 (`p7->d.encrypted->enc_data->algorithm`), `None`
/// when `p7->d.encrypted` is NULL.
pub fn encrypted_alg(p7: &Pkcs7) -> Option<AlgInfo> {
    // SAFETY: p7 is live and of the encrypted type (the caller checked its NID), so the
    // union member read is `encrypted`, NULL or live with live fields.
    let d = unsafe { (*p7.as_ptr()).d };
    // SAFETY: as above.
    let enc = unsafe { d.encrypted };
    // SAFETY: enc is NULL or live.
    let enc = unsafe { enc.as_ref() }?;
    // SAFETY: a live PKCS7_ENCRYPT has live encrypted content.
    let alg = unsafe { (*enc.enc_data).algorithm };
    Some(alg_info(alg))
}

/// An owned `STACK_OF(PKCS12_SAFEBAG)`.
pub struct SafeBags(core::ptr::NonNull<stack_st_PKCS12_SAFEBAG>);

unsafe extern "C" fn free_bag(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, a PKCS12_SAFEBAG.
    unsafe { ffi::PKCS12_SAFEBAG_free(p.cast()) };
}

impl Drop for SafeBags {
    fn drop(&mut self) {
        // SAFETY: the stack and its bags are owned here and freed once.
        unsafe { ffi::OPENSSL_sk_pop_free(self.0.as_ptr().cast(), Some(free_bag)) };
    }
}

impl SafeBags {
    /// The bags, borrowed.
    pub fn bags(&self) -> Vec<SafeBag<'_>> {
        bags_of(self.0.as_ptr())
    }
}

/// `PKCS12_unpack_p7data(p7)`.
pub fn unpack_p7data(p7: &Pkcs7) -> Option<SafeBags> {
    // SAFETY: p7 is live; the stack is the caller's.
    core::ptr::NonNull::new(unsafe { ffi::PKCS12_unpack_p7data(p7.as_ptr()) }).map(SafeBags)
}

/// `PKCS12_unpack_p7encdata(p7, pass, -1)` (`None` for a NULL password, length 0... as
/// upstream passes it).
pub fn unpack_p7encdata(p7: &Pkcs7, pass: Option<&[u8]>) -> Option<SafeBags> {
    let c = opt_c(pass).ok()?;
    // SAFETY: p7 is live; c NULL or a C string.
    core::ptr::NonNull::new(unsafe { ffi::PKCS12_unpack_p7encdata(p7.as_ptr(), ptr_of(&c), -1) })
        .map(SafeBags)
}

fn bags_of(sk: *const stack_st_PKCS12_SAFEBAG) -> Vec<SafeBag<'static>> {
    let mut out = Vec::new();
    if sk.is_null() {
        return out;
    }
    // SAFETY: sk is live.
    let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range.
        let p = unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) };
        out.push(SafeBag(p.cast(), core::marker::PhantomData));
    }
    out
}

/// A safe bag borrowed from its stack.
#[derive(Clone, Copy)]
pub struct SafeBag<'a>(*const PKCS12_SAFEBAG, core::marker::PhantomData<&'a ()>);

impl SafeBag<'_> {
    /// `PKCS12_SAFEBAG_get_nid`.
    pub fn nid(&self) -> c_int {
        // SAFETY: the bag is live while borrowed.
        unsafe { ffi::PKCS12_SAFEBAG_get_nid(self.0) }
    }

    /// `PKCS12_SAFEBAG_get0_attrs`.
    pub fn attrs(&self) -> Option<Vec<Attribute>> {
        // SAFETY: as above.
        attributes_of(unsafe { ffi::PKCS12_SAFEBAG_get0_attrs(self.0) })
    }

    /// The key of a key bag (`EVP_PKCS82PKEY(PKCS12_SAFEBAG_get0_p8inf(bag))`) and its
    /// attributes; `None` if the conversion fails.
    pub fn key(&self) -> Option<(Pkey, Option<Vec<Attribute>>)> {
        // SAFETY: as above; the PKCS#8 structure is owned by the bag.
        let p8 = unsafe { ffi::PKCS12_SAFEBAG_get0_p8inf(self.0) };
        // SAFETY: p8 is NULL or live.
        let key = Pkey::from_raw(unsafe { ffi::EVP_PKCS82PKEY(p8) })?;
        // SAFETY: p8 is live (the conversion succeeded).
        let attrs = attributes_of(unsafe { ffi::PKCS8_pkey_get0_attrs(p8) });
        Some((key, attrs))
    }

    /// The algorithm of a shrouded key bag (`X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag))`).
    pub fn pkcs8_alg(&self) -> AlgInfo {
        // SAFETY: as above.
        let sig = unsafe { ffi::PKCS12_SAFEBAG_get0_pkcs8(self.0) };
        let mut alg = core::ptr::null();
        // SAFETY: sig is the bag's live X509_SIG.
        unsafe { ffi::X509_SIG_get0(sig, &mut alg, core::ptr::null_mut()) };
        alg_info(alg)
    }

    /// The key of a shrouded key bag (`PKCS12_decrypt_skey(bag, pass, -1)`, then
    /// `EVP_PKCS82PKEY`) and its attributes.
    pub fn decrypt_key(&self, pass: Option<&[u8]>) -> Option<(Pkey, Option<Vec<Attribute>>)> {
        let c = opt_c(pass).ok()?;
        // SAFETY: as above; the result is the caller's.
        let p8 = unsafe { ffi::PKCS12_decrypt_skey(self.0, ptr_of(&c), -1) };
        if p8.is_null() {
            return None;
        }
        // SAFETY: p8 is live.
        let key = Pkey::from_raw(unsafe { ffi::EVP_PKCS82PKEY(p8) });
        // SAFETY: as above.
        let attrs = key
            .is_some()
            .then(|| attributes_of(unsafe { ffi::PKCS8_pkey_get0_attrs(p8) }))
            .flatten();
        // SAFETY: p8 is owned here.
        unsafe { ffi::PKCS8_PRIV_KEY_INFO_free(p8) };
        Some((key?, attrs))
    }

    /// `PKCS12_SAFEBAG_get0_attr(bag, nid) != NULL`.
    pub fn has_attr(&self, nid: c_int) -> bool {
        // SAFETY: as above.
        !unsafe { ffi::PKCS12_SAFEBAG_get0_attr(self.0, nid) }.is_null()
    }

    /// `PKCS12_SAFEBAG_get_bag_nid`.
    pub fn bag_nid(&self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::PKCS12_SAFEBAG_get_bag_nid(self.0) }
    }

    /// `PKCS12_SAFEBAG_get1_cert`.
    pub fn cert(&self) -> Option<Cert> {
        // SAFETY: as above; the certificate is a new object.
        Cert::from_raw(unsafe { ffi::PKCS12_SAFEBAG_get1_cert(self.0) })
    }

    /// `PKCS12_SAFEBAG_get0_bag_type`.
    pub fn bag_type(&self) -> Option<Object> {
        // SAFETY: as above.
        Object::dup_from(unsafe { ffi::PKCS12_SAFEBAG_get0_bag_type(self.0) })
    }

    /// `PKCS12_SAFEBAG_get0_bag_obj`.
    pub fn bag_obj(&self) -> Option<Value> {
        // SAFETY: as above.
        value_of(unsafe { ffi::PKCS12_SAFEBAG_get0_bag_obj(self.0) }.cast::<ASN1_TYPE>())
    }

    /// `PKCS12_SAFEBAG_get0_safes`, borrowed.
    pub fn safes(&self) -> Vec<SafeBag<'_>> {
        // SAFETY: as above; the nested bags live as long as this one.
        bags_of(unsafe { ffi::PKCS12_SAFEBAG_get0_safes(self.0) })
    }

    /// `PKCS12_SAFEBAG_get0_type`.
    pub fn type_obj(&self) -> Option<Object> {
        // SAFETY: as above.
        Object::dup_from(unsafe { ffi::PKCS12_SAFEBAG_get0_type(self.0) })
    }
}

/// `PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pass)`.
pub fn write_private_key(
    out: &Bio,
    pkey: &Pkey,
    enc: Option<&Cipher>,
    pass: Option<&[u8]>,
) -> c_int {
    let Ok(c) = opt_c(pass) else {
        return 0;
    };
    // SAFETY: every pointer is NULL or live; with no callback, the user data is the
    // passphrase string, which the call doesn't modify.
    unsafe {
        ffi::PEM_write_bio_PrivateKey(
            out.as_ptr(),
            pkey.as_ptr(),
            enc.map_or(core::ptr::null(), |e| e.as_ptr().cast_const()),
            core::ptr::null(),
            0,
            None,
            ptr_of(&c).cast_mut().cast(),
        )
    }
}

/// `get_cert_chain` of `pkcs12.c`: the verified chain, or the verification error
/// (`X509_V_ERR_UNSPECIFIED` when there is none).
pub fn get_cert_chain(
    cert: &Cert,
    store: &Store,
    untrusted: Option<&CertStack>,
    libctx: Option<&LibCtx>,
    propq: Option<&str>,
) -> Result<CertStack, c_int> {
    let unspecified = crate::abi::X509_V_ERR_UNSPECIFIED;
    let pq = opt_propq(propq).map_err(|_| unspecified)?;
    // SAFETY: libctx NULL or live; pq NULL or a C string.
    let ctx = unsafe { ffi::X509_STORE_CTX_new_ex(ctx_ptr(libctx), ptr_of(&pq)) };
    if ctx.is_null() {
        return Err(unspecified);
    }
    let r = (|| {
        let u = untrusted.map_or(core::ptr::null_mut(), CertStack::as_ptr);
        // SAFETY: ctx is live; the store, certificate and stack (or NULL) outlive it.
        if unsafe { ffi::X509_STORE_CTX_init(ctx, store.as_ptr(), cert.as_ptr(), u) } == 0 {
            return Err(unspecified);
        }
        // SAFETY: ctx is initialized.
        if unsafe { ffi::X509_verify_cert(ctx) } > 0 {
            // SAFETY: as above; the chain is the caller's.
            CertStack::from_raw(unsafe { ffi::X509_STORE_CTX_get1_chain(ctx) }).ok_or(0)
        } else {
            // SAFETY: as above.
            match unsafe { ffi::X509_STORE_CTX_get_error(ctx) } {
                0 => Err(unspecified),
                e => Err(e),
            }
        }
    })();
    // SAFETY: ctx is owned here.
    unsafe { ffi::X509_STORE_CTX_free(ctx) };
    r
}

/// `X509_verify_cert_error_string(e)`.
pub fn verify_cert_error_string(e: c_int) -> String {
    // SAFETY: any value is accepted; the result is a static string.
    crate::util::string_at(unsafe { ffi::X509_verify_cert_error_string(e.into()) })
        .unwrap_or_default()
}

impl CertStack {
    /// `sk_X509_delete(sk, i)`: the certificate removed, now owned by the caller.
    pub fn delete(&self, i: usize) -> Option<Cert> {
        let i = c_int::try_from(i).ok()?;
        // SAFETY: the stack is live; out of range gives NULL.
        Cert::from_raw(unsafe { ffi::OPENSSL_sk_delete(self.as_ptr().cast(), i) }.cast())
    }

    /// `X509_add_certs(self, certs, flags)`.
    pub fn add_certs(&self, certs: &CertStack, flags: c_int) -> bool {
        // SAFETY: both stacks are live; with X509_ADD_FLAG_UP_REF the members are shared.
        unsafe { ffi::X509_add_certs(self.as_ptr(), certs.as_ptr(), flags) == 1 }
    }

    /// `X509_free(sk_X509_shift(sk))`.
    pub fn shift_free(&self) {
        // SAFETY: the stack is live; the member shifted off is owned here.
        let p = unsafe { ffi::OPENSSL_sk_shift(self.as_ptr().cast()) };
        // SAFETY: p is NULL or a certificate owned here.
        unsafe { ffi::X509_free(p.cast()) };
    }
}

impl Cert {
    /// `X509_keyid_set1(x, NULL, 0)` and `X509_alias_set1(x, NULL, 0)`.
    pub fn clear_keyid_alias(&self) {
        // SAFETY: the certificate is live; NULL clears the field.
        unsafe { ffi::X509_keyid_set1(self.as_ptr(), core::ptr::null(), 0) };
        // SAFETY: as above.
        unsafe { ffi::X509_alias_set1(self.as_ptr(), core::ptr::null(), 0) };
    }

    /// `X509_alias_set1(x, name, -1)`.
    pub fn set_alias(&self, name: &str) -> bool {
        let Some(c) = cstring(name) else {
            return false;
        };
        // SAFETY: the certificate is live; c is a C string (length -1: up to its NUL).
        unsafe { ffi::X509_alias_set1(self.as_ptr(), c.as_ptr().cast(), -1) == 1 }
    }
}

impl Pkey {
    /// `EVP_PKEY_add1_attr_by_NID(key, nid, type, bytes, -1)`, `None` for NULL bytes.
    pub fn add1_attr_by_nid(&self, nid: c_int, kind: c_int, bytes: Option<&str>) -> bool {
        let Ok(c) = opt_c(bytes.map(str::as_bytes)) else {
            return false;
        };
        // SAFETY: the key is live; c NULL or a C string.
        unsafe {
            ffi::EVP_PKEY_add1_attr_by_NID(self.as_ptr(), nid, kind, ptr_of(&c).cast(), -1) == 1
        }
    }
}

/// `EVP_read_pw_string(buf, size, prompt, verify)`: the password, `None` if it fails.
pub fn read_pw_string(size: usize, prompt: &str, verify: bool) -> Option<Vec<u8>> {
    let p = cstring(prompt)?;
    let mut buf = vec![0 as c_char; size.max(1)];
    let n = c_int::try_from(buf.len()).ok()?;
    // SAFETY: buf is writable for n bytes; p is a C string.
    let r =
        unsafe { ffi::EVP_read_pw_string(buf.as_mut_ptr(), n, p.as_ptr(), c_int::from(verify)) };
    let s = crate::util::string_at(buf.as_ptr()).map(String::into_bytes);
    buf.fill(0);
    if r != 0 { None } else { s }
}

/// `OSSL_PROVIDER_available(libctx, name)`.
pub fn provider_available(libctx: Option<&LibCtx>, name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: libctx NULL or live; n a C string.
    unsafe { ffi::OSSL_PROVIDER_available(ctx_ptr(libctx), n.as_ptr()) == 1 }
}

/// Whether `EVP_KDF_fetch(libctx, name, propq)` finds the KDF.
pub fn kdf_available(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> bool {
    let (Some(n), Ok(pq)) = (cstring(name), opt_propq(propq)) else {
        return false;
    };
    // SAFETY: as above.
    let k = unsafe { ffi::EVP_KDF_fetch(ctx_ptr(libctx), n.as_ptr(), ptr_of(&pq)) };
    // SAFETY: k is NULL or owned here.
    unsafe { ffi::EVP_KDF_free(k) };
    !k.is_null()
}
