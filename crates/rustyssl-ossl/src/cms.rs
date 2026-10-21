//! CMS (`CMS_ContentInfo` and its signer and recipient infos), for `cms`.

use core::ffi::{c_char, c_int, c_uint, c_void};
use std::ffi::CString;

use crate::abi::{
    ASN1_PCTX_FLAGS_SHOW_ABSENT, CMS_ContentInfo, CMS_SignerInfo, EVP_PKEY_CTRL_CIPHER,
    EVP_PKEY_CTX, GEN_EMAIL, GENERAL_NAME, GENERAL_NAMES, V_ASN1_UNDEF, stack_st_GENERAL_NAMES,
};
use crate::bio::Bio;
use crate::evp::{Cipher, Md};
use crate::ffi;
use crate::object::{Object, string_bytes};
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::cstring;
use crate::x509::{Cert, CertStack, Store, certs_of};

crate::handle!(
    /// An owned `CMS_ContentInfo`.
    Cms, CMS_ContentInfo, CMS_ContentInfo_free
);

fn bio_ptr(b: Option<&Bio>) -> *mut crate::abi::BIO {
    b.map_or(core::ptr::null_mut(), Bio::as_ptr)
}

fn stack_ptr(s: Option<&CertStack>) -> *mut crate::abi::stack_st_X509 {
    s.map_or(core::ptr::null_mut(), CertStack::as_ptr)
}

fn ctx_ptr(libctx: Option<&LibCtx>) -> *mut crate::abi::OSSL_LIB_CTX {
    libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr)
}

fn md_ptr(md: Option<&Md>) -> *const crate::abi::EVP_MD {
    md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const())
}

fn cipher_ptr(c: Option<&Cipher>) -> *const crate::abi::EVP_CIPHER {
    c.map_or(core::ptr::null(), |c| c.as_ptr().cast_const())
}

/// A property query as a C string: `Err` if it holds a NUL.
fn propq_c(propq: Option<&str>) -> Result<Option<CString>, ()> {
    propq.map(|p| cstring(p).ok_or(())).transpose()
}

fn pq_ptr(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

/// The flags as the `int` some calls take (every flag fits).
fn int_flags(flags: c_uint) -> c_int {
    c_int::try_from(flags).unwrap_or(c_int::MAX)
}

/// What a `d2i`/`PEM_read` call with a reused object leaves.
fn reused(result: *mut CMS_ContentInfo, obj: *mut CMS_ContentInfo) -> Option<Cms> {
    if result.is_null() {
        // SAFETY: obj is NULL or the object, still owned here after the failed call.
        unsafe { ffi::CMS_ContentInfo_free(obj) };
        return None;
    }
    Cms::from_ptr(result)
}

/// A copy of `data` in memory from `OPENSSL_malloc`, for the calls that take ownership.
fn openssl_copy(data: &[u8]) -> Option<*mut u8> {
    // SAFETY: any size is accepted; the result is NULL or a block of that size.
    let p = unsafe { ffi::CRYPTO_malloc(data.len().max(1), c"rustyssl-ossl".as_ptr(), 0) };
    if p.is_null() {
        return None;
    }
    let p = p.cast::<u8>();
    // SAFETY: p is a fresh block of at least data.len() bytes, not overlapping data.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
    Some(p)
}

/// One `name:value` key option (`pkey_ctrl_string` of `apps.c`) on a key context.
fn pkey_ctrl_string(pctx: *mut EVP_PKEY_CTX, value: &str) -> c_int {
    let Some((k, v)) = value.split_once(':') else {
        return 0;
    };
    let (Some(k), Some(v)) = (cstring(k), cstring(v)) else {
        return 0;
    };
    // SAFETY: pctx is a live context; the strings are valid.
    unsafe { ffi::EVP_PKEY_CTX_ctrl_str(pctx, k.as_ptr(), v.as_ptr()) }
}

/// `cms_set_pkey_param`: every option, or the first one that fails.
fn set_pkey_params(pctx: *mut EVP_PKEY_CTX, params: &[String]) -> Result<(), String> {
    for p in params {
        if pkey_ctrl_string(pctx, p) <= 0 {
            return Err(p.clone());
        }
    }
    Ok(())
}

/// A recipient's options for [`Cms::add_recipient`].
pub struct RecipientOptions<'a> {
    /// `-keyopt` values.
    pub key_params: Option<&'a [String]>,
    /// The content cipher (its NID goes to the key context).
    pub cipher: &'a Cipher,
    /// `-wrap`.
    pub wrap: Option<&'a Cipher>,
    /// `-recip_ukm`, as bytes.
    pub ukm: Option<&'a [u8]>,
    /// `-recip_kdf`.
    pub kdf: Option<&'a str>,
}

/// Why adding a recipient failed: a key option (named), an unknown KDF (named), or any
/// other error.
pub enum RecipientError {
    KeyParam(String),
    UnknownKdf(String),
    Other,
}

/// One signer's receipt request, as `receipt_request_print` shows it.
pub enum ReceiptRequest {
    None,
    ParseError,
    Request {
        content_id: Vec<u8>,
        all_or_first: c_int,
        /// `None` when the request names no list.
        from: Option<Vec<String>>,
        to: Vec<String>,
    },
}

/// Each `GENERAL_NAME` of a `STACK_OF(GENERAL_NAMES)` as `GENERAL_NAME_print` prints it.
fn gnames_text(gns: *mut stack_st_GENERAL_NAMES) -> Vec<String> {
    let mut out = Vec::new();
    if gns.is_null() {
        return out;
    }
    let Some(mem) = Bio::new_mem() else {
        return out;
    };
    // SAFETY: gns is a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(gns.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the member is a live GENERAL_NAMES stack.
        let gens = unsafe { ffi::OPENSSL_sk_value(gns.cast(), i) };
        // SAFETY: gens is NULL or live.
        let m = unsafe { ffi::OPENSSL_sk_num(gens.cast()) };
        for j in 0..m.max(0) {
            // SAFETY: j is in range; the member is a live GENERAL_NAME.
            let name = unsafe { ffi::OPENSSL_sk_value(gens.cast(), j) };
            // SAFETY: both are live.
            unsafe { ffi::GENERAL_NAME_print(mem.as_ptr(), name.cast()) };
            out.push(String::from_utf8_lossy(&mem.read_to_end()).into_owned());
        }
    }
    out
}

unsafe extern "C" fn free_gens(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, a GENERAL_NAMES.
    unsafe { ffi::GENERAL_NAMES_free(p.cast()) };
}

/// `make_names_stack`: each address as an e-mail `GENERAL_NAMES`.
fn make_names_stack(names: &[String]) -> Option<*mut stack_st_GENERAL_NAMES> {
    // SAFETY: no arguments.
    let ret = unsafe { ffi::OPENSSL_sk_new_null() }.cast::<stack_st_GENERAL_NAMES>();
    if ret.is_null() {
        return None;
    }
    let free_ret = || {
        // SAFETY: ret and the members pushed so far are owned here.
        unsafe { ffi::OPENSSL_sk_pop_free(ret.cast(), Some(free_gens)) };
    };
    for n in names {
        let Some(c) = cstring(n) else {
            free_ret();
            return None;
        };
        // SAFETY: c is a valid C string; no method or context is needed for an e-mail.
        let name = unsafe {
            ffi::a2i_GENERAL_NAME(
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                GEN_EMAIL,
                c.as_ptr(),
                0,
            )
        };
        if name.is_null() {
            free_ret();
            return None;
        }
        // SAFETY: no arguments.
        let gens: *mut GENERAL_NAMES = unsafe { ffi::GENERAL_NAMES_new() };
        // SAFETY: gens is NULL or live; name is owned here.
        if gens.is_null() || unsafe { ffi::OPENSSL_sk_push(gens.cast(), name.cast()) } <= 0 {
            // SAFETY: both are owned here (NULL is allowed).
            unsafe { ffi::GENERAL_NAMES_free(gens) };
            // SAFETY: as above.
            unsafe { ffi::GENERAL_NAME_free(name.cast::<GENERAL_NAME>()) };
            free_ret();
            return None;
        }
        // SAFETY: both stacks are live; on success ret owns gens.
        if unsafe { ffi::OPENSSL_sk_push(ret.cast(), gens.cast()) } <= 0 {
            // SAFETY: gens (with name) is owned here.
            unsafe { ffi::GENERAL_NAMES_free(gens) };
            free_ret();
            return None;
        }
    }
    Some(ret)
}

crate::handle!(
    /// An owned `CMS_ReceiptRequest`.
    Rr, CMS_ReceiptRequest, CMS_ReceiptRequest_free
);

impl Rr {
    /// `make_receipt_request(rr_to, rr_allorfirst, rr_from)`.
    pub fn new(
        to: &[String],
        all_or_first: c_int,
        from: Option<&[String]>,
        libctx: Option<&LibCtx>,
    ) -> Option<Self> {
        let rct_to = make_names_stack(to)?;
        let rct_from = match from {
            Some(f) => match make_names_stack(f) {
                Some(s) => s,
                None => {
                    // SAFETY: rct_to is owned here.
                    unsafe { ffi::OPENSSL_sk_pop_free(rct_to.cast(), Some(free_gens)) };
                    return None;
                }
            },
            None => core::ptr::null_mut(),
        };
        // SAFETY: the stacks are live (or NULL); on success the request takes them.
        let rr = unsafe {
            ffi::CMS_ReceiptRequest_create0_ex(
                core::ptr::null_mut(),
                -1,
                all_or_first,
                rct_from,
                rct_to,
                ctx_ptr(libctx),
            )
        };
        if rr.is_null() {
            // SAFETY: the stacks are still owned here.
            unsafe { ffi::OPENSSL_sk_pop_free(rct_to.cast(), Some(free_gens)) };
            // SAFETY: as above (NULL allowed).
            unsafe { ffi::OPENSSL_sk_pop_free(rct_from.cast(), Some(free_gens)) };
            return None;
        }
        Self::from_ptr(rr)
    }
}

impl Cms {
    /// `CMS_ContentInfo_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        // SAFETY: libctx NULL or live; pq NULL or a C string.
        Self::from_ptr(unsafe { ffi::CMS_ContentInfo_new_ex(ctx_ptr(libctx), pq_ptr(&pq)) })
    }

    /// `SMIME_read_CMS_ex(in, flags, &indata, &self)`, the detached content wanted when
    /// `want_indata`.
    pub fn read_smime_into(
        self,
        input: &Bio,
        flags: c_uint,
        want_indata: bool,
    ) -> (Option<Self>, Option<Bio>) {
        let mut p = self.into_ptr();
        let mut indata = core::ptr::null_mut();
        let pindata = if want_indata {
            &mut indata as *mut *mut crate::abi::BIO
        } else {
            core::ptr::null_mut()
        };
        // SAFETY: the BIO is live; p is an object the call may reuse or free; pindata NULL
        // or a local.
        let r =
            unsafe { ffi::SMIME_read_CMS_ex(input.as_ptr(), int_flags(flags), pindata, &mut p) };
        (reused(r, p), Bio::from_ptr(indata))
    }

    /// `PEM_read_bio_CMS(in, &self, NULL, NULL)`.
    pub fn read_pem_into(self, input: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: as above; no callback.
        let r =
            unsafe { ffi::PEM_read_bio_CMS(input.as_ptr(), &mut p, None, core::ptr::null_mut()) };
        reused(r, p)
    }

    /// `d2i_CMS_bio(in, &self)`.
    pub fn read_der_into(self, input: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: as above.
        let r = unsafe { ffi::d2i_CMS_bio(input.as_ptr(), &mut p) };
        reused(r, p)
    }

    /// `CMS_get1_certs`.
    pub fn certs(&self) -> Option<CertStack> {
        // SAFETY: the object is live; the stack is the caller's.
        CertStack::from_raw(unsafe { ffi::CMS_get1_certs(self.as_ptr()) })
    }

    /// `CMS_data_create_ex(in, flags, libctx, propq)`.
    pub fn data_create(
        input: &Bio,
        flags: c_uint,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        // SAFETY: every pointer is live or NULL where allowed.
        Self::from_ptr(unsafe {
            ffi::CMS_data_create_ex(input.as_ptr(), flags, ctx_ptr(libctx), pq_ptr(&pq))
        })
    }

    /// `CMS_digest_create_ex(in, md, flags, libctx, propq)`.
    pub fn digest_create(
        input: &Bio,
        md: Option<&Md>,
        flags: c_uint,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        // SAFETY: as above.
        Self::from_ptr(unsafe {
            ffi::CMS_digest_create_ex(
                input.as_ptr(),
                md_ptr(md),
                flags,
                ctx_ptr(libctx),
                pq_ptr(&pq),
            )
        })
    }

    /// `CMS_compress(in, -1, flags)`.
    pub fn compress(input: &Bio, flags: c_uint) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::CMS_compress(input.as_ptr(), -1, flags) })
    }

    /// `CMS_encrypt_ex(NULL, in, cipher, flags, libctx, propq)`.
    pub fn encrypt_partial(
        input: &Bio,
        cipher: &Cipher,
        flags: c_uint,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        // SAFETY: as above.
        Self::from_ptr(unsafe {
            ffi::CMS_encrypt_ex(
                core::ptr::null_mut(),
                input.as_ptr(),
                cipher.as_ptr(),
                flags,
                ctx_ptr(libctx),
                pq_ptr(&pq),
            )
        })
    }

    /// One recipient of `cms -encrypt`: `CMS_add1_recipient(cms, x, key, originator,
    /// flags)`, then its key options, the content cipher's NID, the key-wrap cipher, and the
    /// KEM recipient's UKM and KDF.
    pub fn add_recipient(
        &self,
        x: &Cert,
        key: Option<&Pkey>,
        originator: Option<&Cert>,
        flags: c_uint,
        o: &RecipientOptions<'_>,
    ) -> Result<(), RecipientError> {
        // SAFETY: every pointer is live or NULL where allowed; the info is owned by cms.
        let ri = unsafe {
            ffi::CMS_add1_recipient(
                self.as_ptr(),
                x.as_ptr(),
                key.map_or(core::ptr::null_mut(), Pkey::as_ptr),
                originator.map_or(core::ptr::null_mut(), Cert::as_ptr),
                flags,
            )
        };
        if ri.is_null() {
            return Err(RecipientError::Other);
        }
        // SAFETY: ri is live.
        let ri_type = unsafe { ffi::CMS_RecipientInfo_type(ri) };
        // SAFETY: as above.
        let pctx = unsafe { ffi::CMS_RecipientInfo_get0_pkey_ctx(ri) };
        if let (false, Some(params)) = (pctx.is_null(), o.key_params) {
            set_pkey_params(pctx, params).map_err(RecipientError::KeyParam)?;
        }
        // SAFETY: the cipher is live.
        let nid = unsafe { ffi::EVP_CIPHER_get_nid(o.cipher.as_ptr()) };
        // SAFETY: pctx is NULL or live (NULL gives -2); no pointer argument.
        let res = unsafe {
            ffi::EVP_PKEY_CTX_ctrl(
                pctx,
                -1,
                -1,
                EVP_PKEY_CTRL_CIPHER,
                nid,
                core::ptr::null_mut(),
            )
        };
        if res <= 0 && res != -2 {
            return Err(RecipientError::Other);
        }
        if let Some(w) = o.wrap {
            let wctx = if ri_type == crate::abi::CMS_RECIPINFO_AGREE {
                // SAFETY: ri is live and of that type.
                unsafe { ffi::CMS_RecipientInfo_kari_get0_ctx(ri) }
            } else if ri_type == crate::abi::CMS_RECIPINFO_KEM {
                // SAFETY: as above.
                unsafe { ffi::CMS_RecipientInfo_kemri_get0_ctx(ri) }
            } else {
                core::ptr::null_mut()
            };
            if !wctx.is_null() {
                // SAFETY: wctx is the info's live context; w is live.
                let r = unsafe {
                    ffi::EVP_EncryptInit_ex(
                        wctx,
                        w.as_ptr(),
                        core::ptr::null_mut(),
                        core::ptr::null(),
                        core::ptr::null(),
                    )
                };
                if r != 1 {
                    return Err(RecipientError::Other);
                }
            }
        }
        if ri_type == crate::abi::CMS_RECIPINFO_KEM {
            if let Some(ukm) = o.ukm {
                let len = c_int::try_from(ukm.len()).map_err(|_| RecipientError::Other)?;
                // SAFETY: ri is live; ukm is valid for len bytes (copied).
                if unsafe { ffi::CMS_RecipientInfo_kemri_set_ukm(ri, ukm.as_ptr(), len) } != 1 {
                    return Err(RecipientError::Other);
                }
            }
            if let Some(kdf) = o.kdf {
                // SAFETY: ri is live; the algorithm is owned by it.
                let alg = unsafe { ffi::CMS_RecipientInfo_kemri_get0_kdf_alg(ri) };
                let Some(obj) = Object::from_txt(kdf, false) else {
                    return Err(RecipientError::UnknownKdf(kdf.to_owned()));
                };
                // SAFETY: alg is live; on success it takes obj.
                if unsafe {
                    ffi::X509_ALGOR_set0(alg, obj.as_ptr(), V_ASN1_UNDEF, core::ptr::null_mut())
                } != 1
                {
                    return Err(RecipientError::Other);
                }
                core::mem::forget(obj);
            }
        }
        Ok(())
    }

    /// `CMS_add0_recipient_key(cms, NID_undef, key, id, NULL, NULL, NULL)` (with copies).
    pub fn add_recipient_key(&self, key: &[u8], id: &[u8]) -> bool {
        let (Some(k), Some(i)) = (openssl_copy(key), openssl_copy(id)) else {
            return false;
        };
        // SAFETY: k and i are blocks from OPENSSL_malloc of the lengths given; on success
        // the recipient info takes them.
        let r = unsafe {
            ffi::CMS_add0_recipient_key(
                self.as_ptr(),
                crate::abi::NID_undef,
                k,
                key.len(),
                i,
                id.len(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if r.is_null() {
            crate::util::openssl_free(k.cast());
            crate::util::openssl_free(i.cast());
            return false;
        }
        true
    }

    /// `CMS_add0_recipient_password(cms, -1, NID_undef, NID_undef, strdup(pass), -1, kek)`.
    pub fn add_recipient_password(&self, pass: &str, kek: Option<&Cipher>) -> bool {
        let Some(c) = cstring(pass) else {
            return false;
        };
        // SAFETY: c is a valid C string; the copy is the caller's.
        let dup = unsafe { ffi::CRYPTO_strdup(c.as_ptr(), c"rustyssl-ossl".as_ptr(), 0) };
        if dup.is_null() {
            return false;
        }
        // SAFETY: dup is a NUL-terminated copy from OPENSSL_malloc; on success the info
        // takes it.
        let r = unsafe {
            ffi::CMS_add0_recipient_password(
                self.as_ptr(),
                -1,
                crate::abi::NID_undef,
                crate::abi::NID_undef,
                dup.cast(),
                -1,
                cipher_ptr(kek),
            )
        };
        if r.is_null() {
            crate::util::openssl_free(dup.cast());
            return false;
        }
        true
    }

    /// `CMS_final(cms, data, NULL, flags)`.
    pub fn finalize(&self, data: Option<&Bio>, flags: c_uint) -> bool {
        // SAFETY: as above.
        unsafe { ffi::CMS_final(self.as_ptr(), bio_ptr(data), core::ptr::null_mut(), flags) == 1 }
    }

    /// `CMS_final_digest(cms, digest, NULL, flags)`.
    pub fn finalize_digest(&self, digest: &[u8], flags: c_uint) -> bool {
        let Ok(len) = c_uint::try_from(digest.len()) else {
            return false;
        };
        // SAFETY: the object is live; digest is valid for len bytes.
        unsafe {
            ffi::CMS_final_digest(
                self.as_ptr(),
                digest.as_ptr(),
                len,
                core::ptr::null_mut(),
                flags,
            ) == 1
        }
    }

    /// `CMS_EncryptedData_encrypt_ex(in, cipher, key, flags, libctx, propq)`.
    pub fn encrypted_data_encrypt(
        input: &Bio,
        cipher: Option<&Cipher>,
        key: Option<&[u8]>,
        flags: c_uint,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        let (k, klen) = key.map_or((core::ptr::null(), 0), |k| (k.as_ptr(), k.len()));
        // SAFETY: every pointer is live or NULL where allowed.
        Self::from_ptr(unsafe {
            ffi::CMS_EncryptedData_encrypt_ex(
                input.as_ptr(),
                cipher_ptr(cipher),
                k,
                klen,
                flags,
                ctx_ptr(libctx),
                pq_ptr(&pq),
            )
        })
    }

    /// The first signer info (`sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0)`):
    /// `None` when there is no stack.
    fn first_signer_info(&self) -> Option<*mut CMS_SignerInfo> {
        // SAFETY: the object is live; the stack is owned by it.
        let sis = unsafe { ffi::CMS_get0_SignerInfos(self.as_ptr()) };
        if sis.is_null() {
            return None;
        }
        // SAFETY: sis is live; out of range gives NULL.
        Some(unsafe { ffi::OPENSSL_sk_value(sis.cast(), 0) }.cast())
    }

    /// `CMS_sign_receipt(first signer info, signer, key, certs, flags)`: `Err(true)` when the
    /// object has no signer infos.
    pub fn sign_receipt(
        &self,
        signer: &Cert,
        key: Option<&Pkey>,
        certs: Option<&CertStack>,
        flags: c_uint,
    ) -> Option<Self> {
        let si = self.first_signer_info()?;
        // SAFETY: si is NULL or a live signer info; the rest are live or NULL.
        Self::from_ptr(unsafe {
            ffi::CMS_sign_receipt(
                si,
                signer.as_ptr(),
                key.map_or(core::ptr::null_mut(), Pkey::as_ptr),
                stack_ptr(certs),
                flags,
            )
        })
    }

    /// `CMS_sign_ex(NULL, NULL, certs, in, flags, libctx, propq)`.
    pub fn sign_partial(
        certs: Option<&CertStack>,
        input: Option<&Bio>,
        flags: c_uint,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = propq_c(propq).ok()?;
        // SAFETY: as above.
        Self::from_ptr(unsafe {
            ffi::CMS_sign_ex(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                stack_ptr(certs),
                bio_ptr(input),
                flags,
                ctx_ptr(libctx),
                pq_ptr(&pq),
            )
        })
    }

    /// `CMS_set1_eContentType`.
    pub fn set1_econtent_type(&self, obj: &Object) -> bool {
        // SAFETY: both are live; the object is copied.
        unsafe { ffi::CMS_set1_eContentType(self.as_ptr(), obj.as_ptr()) == 1 }
    }

    /// One signer of `cms -sign`/`-resign`: `CMS_add1_signer(cms, signer, key, md, flags)`,
    /// then its key options and receipt request. `Err(None)` when the signer can't be added,
    /// `Err(Some(param))` for a key option that fails, `Ok(false)` when the receipt request
    /// can't be added.
    pub fn add_signer(
        &self,
        signer: &Cert,
        key: &Pkey,
        md: Option<&Md>,
        flags: c_uint,
        key_params: Option<&[String]>,
        rr: Option<&Rr>,
    ) -> Result<bool, Option<String>> {
        // SAFETY: every pointer is live or NULL where allowed; the info is owned by cms.
        let si = unsafe {
            ffi::CMS_add1_signer(
                self.as_ptr(),
                signer.as_ptr(),
                key.as_ptr(),
                md_ptr(md),
                flags,
            )
        };
        if si.is_null() {
            return Err(None);
        }
        if let Some(params) = key_params {
            // SAFETY: si is live.
            let pctx = unsafe { ffi::CMS_SignerInfo_get0_pkey_ctx(si) };
            set_pkey_params(pctx, params).map_err(Some)?;
        }
        if let Some(rr) = rr {
            // SAFETY: both are live; the request is encoded into the signer info.
            if unsafe { ffi::CMS_add1_ReceiptRequest(si, rr.as_ptr()) } != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `CMS_decrypt(cms, key, cert, dcont, out, flags)`.
    pub fn decrypt(
        &self,
        key: Option<&Pkey>,
        cert: Option<&Cert>,
        dcont: Option<&Bio>,
        out: Option<&Bio>,
        flags: c_uint,
    ) -> bool {
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe {
            ffi::CMS_decrypt(
                self.as_ptr(),
                key.map_or(core::ptr::null_mut(), Pkey::as_ptr),
                cert.map_or(core::ptr::null_mut(), Cert::as_ptr),
                bio_ptr(dcont),
                bio_ptr(out),
                flags,
            ) == 1
        }
    }

    /// `CMS_decrypt_set1_key(cms, key, id)`; no id (NULL) tries every KEK recipient.
    pub fn decrypt_set1_key(&self, key: &[u8], id: Option<&[u8]>) -> bool {
        let mut k = key.to_vec();
        let (i, ilen) = id.map_or((core::ptr::null(), 0), |i| (i.as_ptr(), i.len()));
        // SAFETY: the object is live; the buffers are NULL or valid for their lengths
        // (copied).
        unsafe { ffi::CMS_decrypt_set1_key(self.as_ptr(), k.as_mut_ptr(), k.len(), i, ilen) == 1 }
    }

    /// `CMS_decrypt_set1_pkey_and_peer(cms, key, cert, peer)`.
    pub fn decrypt_set1_pkey_and_peer(
        &self,
        key: &Pkey,
        cert: Option<&Cert>,
        peer: Option<&Cert>,
    ) -> bool {
        // SAFETY: as above.
        unsafe {
            ffi::CMS_decrypt_set1_pkey_and_peer(
                self.as_ptr(),
                key.as_ptr(),
                cert.map_or(core::ptr::null_mut(), Cert::as_ptr),
                peer.map_or(core::ptr::null_mut(), Cert::as_ptr),
            ) == 1
        }
    }

    /// `CMS_decrypt_set1_password(cms, pass, -1)`.
    pub fn decrypt_set1_password(&self, pass: &str) -> bool {
        let Some(c) = cstring(pass) else {
            return false;
        };
        let mut b = c.into_bytes_with_nul();
        // SAFETY: the object is live; b is a NUL-terminated copy (the library copies it).
        unsafe { ffi::CMS_decrypt_set1_password(self.as_ptr(), b.as_mut_ptr(), -1) == 1 }
    }

    /// `CMS_data(cms, out, flags)`.
    pub fn data(&self, out: &Bio, flags: c_uint) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::CMS_data(self.as_ptr(), out.as_ptr(), flags) == 1 }
    }

    /// `CMS_uncompress(cms, dcont, out, flags)`.
    pub fn uncompress(&self, dcont: Option<&Bio>, out: &Bio, flags: c_uint) -> bool {
        // SAFETY: as above.
        unsafe { ffi::CMS_uncompress(self.as_ptr(), bio_ptr(dcont), out.as_ptr(), flags) == 1 }
    }

    /// `CMS_digest_verify(cms, dcont, out, flags) > 0`.
    pub fn digest_verify(&self, dcont: Option<&Bio>, out: &Bio, flags: c_uint) -> bool {
        // SAFETY: as above.
        unsafe { ffi::CMS_digest_verify(self.as_ptr(), bio_ptr(dcont), out.as_ptr(), flags) > 0 }
    }

    /// `CMS_EncryptedData_decrypt(cms, key, dcont, out, flags)`.
    pub fn encrypted_data_decrypt(
        &self,
        key: Option<&[u8]>,
        dcont: Option<&Bio>,
        out: &Bio,
        flags: c_uint,
    ) -> bool {
        let (k, klen) = key.map_or((core::ptr::null(), 0), |k| (k.as_ptr(), k.len()));
        // SAFETY: as above.
        unsafe {
            ffi::CMS_EncryptedData_decrypt(
                self.as_ptr(),
                k,
                klen,
                bio_ptr(dcont),
                out.as_ptr(),
                flags,
            ) == 1
        }
    }

    /// `CMS_verify(cms, certs, store, dcont, out, flags) > 0`.
    pub fn verify(
        &self,
        certs: Option<&CertStack>,
        store: Option<&Store>,
        dcont: Option<&Bio>,
        out: Option<&Bio>,
        flags: c_uint,
    ) -> bool {
        // SAFETY: as above.
        unsafe {
            ffi::CMS_verify(
                self.as_ptr(),
                stack_ptr(certs),
                store.map_or(core::ptr::null_mut(), Store::as_ptr),
                bio_ptr(dcont),
                bio_ptr(out),
                flags,
            ) > 0
        }
    }

    /// `CMS_get0_signers`, each as a new reference.
    pub fn signers(&self) -> Vec<Cert> {
        // SAFETY: the object is live; the stack is the caller's, its members borrowed.
        let sk = unsafe { ffi::CMS_get0_signers(self.as_ptr()) };
        let v = certs_of(sk);
        // SAFETY: only the stack is freed (sk_X509_free; NULL allowed).
        unsafe { ffi::OPENSSL_sk_free(sk.cast()) };
        v
    }

    /// Each signer's receipt request (`receipt_request_print`).
    pub fn receipt_requests(&self) -> Vec<ReceiptRequest> {
        let mut out = Vec::new();
        // SAFETY: the object is live; the stack is owned by it.
        let sis = unsafe { ffi::CMS_get0_SignerInfos(self.as_ptr()) };
        // SAFETY: sis is NULL or live (NULL counts as empty: -1).
        let n = unsafe { ffi::OPENSSL_sk_num(sis.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; the member is a live signer info.
            let si = unsafe { ffi::OPENSSL_sk_value(sis.cast(), i) };
            let mut rr = core::ptr::null_mut();
            // SAFETY: si is live; rr gets a new request or stays NULL.
            let rv = unsafe { ffi::CMS_get1_ReceiptRequest(si.cast(), &mut rr) };
            let item = if rv == 0 {
                ReceiptRequest::None
            } else if rv < 0 {
                ReceiptRequest::ParseError
            } else {
                let mut scid = core::ptr::null_mut();
                let mut allorfirst: c_int = 0;
                let mut rlist = core::ptr::null_mut();
                let mut rto = core::ptr::null_mut();
                // SAFETY: rr is live; the outputs are borrowed from it.
                unsafe {
                    ffi::CMS_ReceiptRequest_get0_values(
                        rr,
                        &mut scid,
                        &mut allorfirst,
                        &mut rlist,
                        &mut rto,
                    )
                };
                ReceiptRequest::Request {
                    content_id: string_bytes(scid),
                    all_or_first: allorfirst,
                    from: (!rlist.is_null()).then(|| gnames_text(rlist)),
                    to: gnames_text(rto),
                }
            };
            // SAFETY: rr is NULL or owned here.
            unsafe { ffi::CMS_ReceiptRequest_free(rr) };
            out.push(item);
        }
        out
    }

    /// `CMS_verify_receipt(rcms, ocms, certs, store, flags) > 0`, `self` the receipt.
    pub fn verify_receipt(
        &self,
        original: &Cms,
        certs: Option<&CertStack>,
        store: Option<&Store>,
        flags: c_uint,
    ) -> bool {
        // SAFETY: as above.
        unsafe {
            ffi::CMS_verify_receipt(
                self.as_ptr(),
                original.as_ptr(),
                stack_ptr(certs),
                store.map_or(core::ptr::null_mut(), Store::as_ptr),
                flags,
            ) > 0
        }
    }

    /// `CMS_ContentInfo_print_ctx(out, cms, 0, pctx)`, with a print context showing absent
    /// fields and the name flags `nmflags` (none when `None`).
    pub fn print(&self, out: &Bio, nmflags: Option<core::ffi::c_ulong>) -> c_int {
        let pctx = match nmflags {
            Some(f) => {
                // SAFETY: no arguments.
                let p = unsafe { ffi::ASN1_PCTX_new() };
                if !p.is_null() {
                    let show =
                        core::ffi::c_ulong::try_from(ASN1_PCTX_FLAGS_SHOW_ABSENT).unwrap_or(0);
                    // SAFETY: p is live.
                    unsafe { ffi::ASN1_PCTX_set_flags(p, show) };
                    // SAFETY: as above.
                    unsafe { ffi::ASN1_PCTX_set_str_flags(p, f) };
                    // SAFETY: as above.
                    unsafe { ffi::ASN1_PCTX_set_nm_flags(p, f) };
                }
                p
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: both are live; pctx NULL or live.
        let r = unsafe { ffi::CMS_ContentInfo_print_ctx(out.as_ptr(), self.as_ptr(), 0, pctx) };
        // SAFETY: pctx is NULL or owned here.
        unsafe { ffi::ASN1_PCTX_free(pctx) };
        r
    }

    /// `SMIME_write_CMS(out, cms, data, flags)`.
    pub fn write_smime(&self, out: &Bio, data: Option<&Bio>, flags: c_uint) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::SMIME_write_CMS(out.as_ptr(), self.as_ptr(), bio_ptr(data), int_flags(flags))
        }
    }

    /// `PEM_write_bio_CMS_stream(out, cms, in, flags)`.
    pub fn write_pem_stream(&self, out: &Bio, input: Option<&Bio>, flags: c_uint) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::PEM_write_bio_CMS_stream(
                out.as_ptr(),
                self.as_ptr(),
                bio_ptr(input),
                int_flags(flags),
            )
        }
    }

    /// `i2d_CMS_bio_stream(out, cms, in, flags)`.
    pub fn write_der_stream(&self, out: &Bio, input: Option<&Bio>, flags: c_uint) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::i2d_CMS_bio_stream(
                out.as_ptr(),
                self.as_ptr(),
                bio_ptr(input),
                int_flags(flags),
            )
        }
    }
}

/// `BIO_dump_indent(bio, data, len, indent)`.
pub fn dump_indent(bio: &Bio, data: &[u8], indent: c_int) -> c_int {
    let Ok(len) = c_int::try_from(data.len()) else {
        return -1;
    };
    // SAFETY: both are live; data is valid for len bytes.
    unsafe { ffi::BIO_dump_indent(bio.as_ptr(), data.as_ptr().cast(), len, indent) }
}
