//! PKCS#7 (`PKCS7`), for `pkcs7`, `smime`, and `pkcs12`.

use core::ffi::c_int;

use crate::abi::{
    NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, PKCS7, X509_STORE_CTX,
    X509_V_ERR_NO_EXPLICIT_POLICY, X509_V_OK,
};
use crate::bio::Bio;
use crate::evp::{Cipher, Md};
use crate::ffi;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::cstring;
use crate::verify::VerifyParam;
use crate::x509::{Cert, CertStack, Crl, Store, certs_of, crls_of};

crate::handle!(
    /// An owned `PKCS7`.
    Pkcs7, PKCS7, PKCS7_free
);

/// What a `d2i`/`PEM_read` call with a reused object leaves: the result, else the object is
/// freed (if the call didn't already).
fn reused(result: *mut PKCS7, obj: *mut PKCS7) -> Option<Pkcs7> {
    if result.is_null() {
        // SAFETY: obj is NULL or the object, still owned here after the failed call.
        unsafe { ffi::PKCS7_free(obj) };
        return None;
    }
    Pkcs7::from_ptr(result)
}

impl Pkcs7 {
    /// Takes ownership of a `PKCS7` the caller got from the library.
    pub fn from_raw(p: *mut PKCS7) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `PKCS7_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        // SAFETY: libctx is NULL or live; pq NULL or a valid C string.
        Self::from_ptr(unsafe {
            ffi::PKCS7_new_ex(
                libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `d2i_PKCS7_bio(bio, &self)`: the object filled in, or `None` (it is freed).
    pub fn read_der_into(self, bio: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: the BIO is live; p is an object the call may reuse or free.
        let r = unsafe { ffi::d2i_PKCS7_bio(bio.as_ptr(), &mut p) };
        reused(r, p)
    }

    /// `PEM_read_bio_PKCS7(bio, &self, NULL, NULL)`.
    pub fn read_pem_into(self, bio: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: as above; no callback.
        let r =
            unsafe { ffi::PEM_read_bio_PKCS7(bio.as_ptr(), &mut p, None, core::ptr::null_mut()) };
        reused(r, p)
    }

    /// `d2i_PKCS7_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_PKCS7_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `PEM_read_bio_PKCS7(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_PKCS7(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `PKCS7_print_ctx(out, p7, indent, NULL)`.
    pub fn print_ctx(&self, out: &Bio, indent: c_int) -> c_int {
        // SAFETY: both are live; no print context.
        unsafe { ffi::PKCS7_print_ctx(out.as_ptr(), self.as_ptr(), indent, core::ptr::null()) }
    }

    /// `i2d_PKCS7_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PKCS7_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_PKCS7`.
    pub fn write_pem(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PKCS7(out.as_ptr(), self.as_ptr()) }
    }

    /// `OBJ_obj2nid(p7->type)`.
    pub fn type_nid(&self) -> c_int {
        // SAFETY: the object is live; its public layout has the type field.
        let t = unsafe { (*self.as_ptr()).type_ };
        // SAFETY: t is NULL or the object's live type.
        unsafe { ffi::OBJ_obj2nid(t) }
    }

    /// The certificates and CRLs of a signed or signed-and-enveloped object (`p7->d.sign`
    /// or `p7->d.signed_and_enveloped`), as `pkcs7 -print_certs` reads them: `None` for a
    /// stack that is absent.
    pub fn certs_and_crls(&self) -> (Option<Vec<Cert>>, Option<Vec<Crl>>) {
        let nid = self.type_nid();
        // SAFETY: the object is live.
        let d = unsafe { (*self.as_ptr()).d };
        let (certs, crls) = if nid == NID_pkcs7_signed {
            // SAFETY: the union member read is the one the type selects.
            let s = unsafe { d.sign };
            // SAFETY: s is NULL or the object's live signed content.
            match unsafe { s.as_ref() } {
                Some(s) => (s.cert, s.crl),
                None => (core::ptr::null_mut(), core::ptr::null_mut()),
            }
        } else if nid == NID_pkcs7_signedAndEnveloped {
            // SAFETY: as above.
            let s = unsafe { d.signed_and_enveloped };
            // SAFETY: as above.
            match unsafe { s.as_ref() } {
                Some(s) => (s.cert, s.crl),
                None => (core::ptr::null_mut(), core::ptr::null_mut()),
            }
        } else {
            (core::ptr::null_mut(), core::ptr::null_mut())
        };
        // The stacks are NULL or live, owned by the object.
        (
            (!certs.is_null()).then(|| certs_of(certs)),
            (!crls.is_null()).then(|| crls_of(crls)),
        )
    }
}

// S/MIME (`smime`).

/// A `BIO`'s pointer, or NULL.
fn bio_ptr(b: Option<&Bio>) -> *mut crate::abi::BIO {
    b.map_or(core::ptr::null_mut(), Bio::as_ptr)
}

fn stack_ptr(s: Option<&CertStack>) -> *mut crate::abi::stack_st_X509 {
    s.map_or(core::ptr::null_mut(), CertStack::as_ptr)
}

fn propq_c(propq: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match propq {
        Some(p) => Some(Some(cstring(p)?)),
        None => Some(None),
    }
}

impl Pkcs7 {
    /// `SMIME_read_PKCS7_ex(in, &indata, &self)`: the object, and the detached content if
    /// any; `None` (the object freed) on failure.
    pub fn read_smime_into(self, input: &Bio) -> (Option<Self>, Option<Bio>) {
        let mut p = self.into_ptr();
        let mut indata = core::ptr::null_mut();
        // SAFETY: the BIO is live; p is an object the call may reuse or free; indata gets a
        // new BIO or stays NULL.
        let r = unsafe { ffi::SMIME_read_PKCS7_ex(input.as_ptr(), &mut indata, &mut p) };
        (reused(r, p), Bio::from_ptr(indata))
    }

    /// `PKCS7_encrypt_ex(certs, in, cipher, flags, libctx, propq)`.
    pub fn encrypt(
        certs: &CertStack,
        input: &Bio,
        cipher: &Cipher,
        flags: c_int,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq)?;
        // SAFETY: every pointer is live or NULL where allowed.
        Self::from_ptr(unsafe {
            ffi::PKCS7_encrypt_ex(
                certs.as_ptr(),
                input.as_ptr(),
                cipher.as_ptr(),
                flags,
                libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `PKCS7_sign_ex(NULL, NULL, certs, in, flags, libctx, propq)`.
    pub fn sign_partial(
        certs: Option<&CertStack>,
        input: &Bio,
        flags: c_int,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq)?;
        // SAFETY: as above.
        Self::from_ptr(unsafe {
            ffi::PKCS7_sign_ex(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                stack_ptr(certs),
                input.as_ptr(),
                flags,
                libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `PKCS7_add_certificate` (which takes a new reference).
    pub fn add_certificate(&self, x: &Cert) -> bool {
        // SAFETY: both are live; the object up-refs the certificate.
        unsafe { ffi::PKCS7_add_certificate(self.as_ptr(), x.as_ptr()) == 1 }
    }

    /// `PKCS7_sign_add_signer(p7, signer, key, md, flags) != NULL`.
    pub fn sign_add_signer(
        &self,
        signer: &Cert,
        key: &Pkey,
        md: Option<&Md>,
        flags: c_int,
    ) -> bool {
        // SAFETY: every pointer is live or NULL where allowed; the signer info is owned by
        // the object.
        !unsafe {
            ffi::PKCS7_sign_add_signer(
                self.as_ptr(),
                signer.as_ptr(),
                key.as_ptr(),
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
                flags,
            )
        }
        .is_null()
    }

    /// `PKCS7_final`.
    pub fn finalize(&self, data: &Bio, flags: c_int) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::PKCS7_final(self.as_ptr(), data.as_ptr(), flags) == 1 }
    }

    /// `PKCS7_decrypt(p7, key, cert, out, flags)`.
    pub fn decrypt(
        &self,
        key: Option<&Pkey>,
        cert: Option<&Cert>,
        out: &Bio,
        flags: c_int,
    ) -> bool {
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe {
            ffi::PKCS7_decrypt(
                self.as_ptr(),
                key.map_or(core::ptr::null_mut(), Pkey::as_ptr),
                cert.map_or(core::ptr::null_mut(), Cert::as_ptr),
                out.as_ptr(),
                flags,
            ) == 1
        }
    }

    /// `PKCS7_verify(p7, certs, store, indata, out, flags)`.
    pub fn verify(
        &self,
        certs: Option<&CertStack>,
        store: Option<&Store>,
        indata: Option<&Bio>,
        out: Option<&Bio>,
        flags: c_int,
    ) -> bool {
        // SAFETY: as above.
        unsafe {
            ffi::PKCS7_verify(
                self.as_ptr(),
                stack_ptr(certs),
                store.map_or(core::ptr::null_mut(), Store::as_ptr),
                bio_ptr(indata),
                bio_ptr(out),
                flags,
            ) == 1
        }
    }

    /// `PKCS7_get0_signers(p7, certs, flags)`, each as a new reference (`None` on failure).
    pub fn signers(&self, certs: Option<&CertStack>, flags: c_int) -> Option<Vec<Cert>> {
        // SAFETY: as above; the stack is the caller's, its members borrowed.
        let sk = unsafe { ffi::PKCS7_get0_signers(self.as_ptr(), stack_ptr(certs), flags) };
        if sk.is_null() {
            return None;
        }
        let v = certs_of(sk);
        // SAFETY: only the stack is freed (sk_X509_free).
        unsafe { ffi::OPENSSL_sk_free(sk.cast()) };
        Some(v)
    }

    /// `SMIME_write_PKCS7(out, p7, data, flags)`.
    pub fn write_smime(&self, out: &Bio, data: Option<&Bio>, flags: c_int) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SMIME_write_PKCS7(out.as_ptr(), self.as_ptr(), bio_ptr(data), flags) }
    }

    /// `PEM_write_bio_PKCS7_stream(out, p7, in, flags)`.
    pub fn write_pem_stream(&self, out: &Bio, input: Option<&Bio>, flags: c_int) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::PEM_write_bio_PKCS7_stream(out.as_ptr(), self.as_ptr(), bio_ptr(input), flags)
        }
    }

    /// `i2d_PKCS7_bio_stream(out, p7, in, flags)`.
    pub fn write_der_stream(&self, out: &Bio, input: Option<&Bio>, flags: c_int) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::i2d_PKCS7_bio_stream(out.as_ptr(), self.as_ptr(), bio_ptr(input), flags) }
    }
}

/// `nodes_print` of `apps.c`, to standard error.
fn nodes_print(err: &Bio, name: &str, nodes: *mut crate::abi::stack_st_X509_POLICY_NODE) {
    let _ = err.write_all(format!("{name} Policies:").as_bytes());
    if nodes.is_null() {
        let _ = err.write_all(b" <empty>\n");
        return;
    }
    let _ = err.write_all(b"\n");
    // SAFETY: nodes is a live stack (owned by the policy tree).
    let n = unsafe { ffi::OPENSSL_sk_num(nodes.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the member is a live node.
        let node = unsafe { ffi::OPENSSL_sk_value(nodes.cast(), i) };
        // SAFETY: both are live.
        unsafe { ffi::X509_POLICY_NODE_print(err.as_ptr(), node.cast(), 2) };
    }
}

/// The verify callback of `smime` and `cms` (`smime_cb`, `cms_cb`): prints the policies
/// (`policies_print` of `apps.c`) when the chain verified or no explicit policy was found.
unsafe extern "C" fn policy_print_cb(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: ctx is the live context the library calls back with.
    let error = unsafe { ffi::X509_STORE_CTX_get_error(ctx) };
    if error != X509_V_ERR_NO_EXPLICIT_POLICY && (error != X509_V_OK || ok != 2) {
        return ok;
    }
    let Some(err) = Bio::new_fd(2, false) else {
        return ok;
    };
    // SAFETY: as above.
    let tree = unsafe { ffi::X509_STORE_CTX_get0_policy_tree(ctx) };
    // SAFETY: as above.
    let explicit = unsafe { ffi::X509_STORE_CTX_get_explicit_policy(ctx) };
    let yes = if explicit != 0 { "True" } else { "False" };
    let _ = err.write_all(format!("Require explicit Policy: {yes}\n").as_bytes());
    // SAFETY: tree is NULL or live (NULL gives NULL).
    nodes_print(&err, "Authority", unsafe {
        ffi::X509_policy_tree_get0_policies(tree)
    });
    // SAFETY: as above.
    nodes_print(&err, "User", unsafe {
        ffi::X509_policy_tree_get0_user_policies(tree)
    });
    ok
}

impl Store {
    /// `X509_STORE_set_verify_cb(store, smime_cb)`: the callback of `smime` and `cms`, which
    /// prints the policies.
    pub fn set_policy_print_cb(&self) {
        // SAFETY: the store is live; the callback is a static function.
        unsafe { ffi::X509_STORE_set_verify_cb(self.as_ptr(), Some(policy_print_cb)) };
    }

    /// `X509_STORE_set1_param(store, vpm)`.
    pub fn set1_param(&self, vpm: &VerifyParam) -> bool {
        // SAFETY: both are live; the store copies the parameters.
        unsafe { ffi::X509_STORE_set1_param(self.as_ptr(), vpm.as_ptr()) == 1 }
    }
}
