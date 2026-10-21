//! OCSP (requests, responses, certificate IDs, and the responder's signing), and the ASN.1
//! items both sides of HTTP exchange. (The responder reads the CA's index with `txt_db`.)

use core::ffi::{c_int, c_long, c_ulong, c_void};

use crate::abi::{
    ASN1_GENERALIZEDTIME, ASN1_ITEM, BIO, NID_hold_instruction_code, NID_invalidity_date,
    OCSP_SINGLERESP,
};
use crate::bio::Bio;
use crate::evp::Md;
use crate::ffi;
use crate::object::Object;
use crate::pkey::{MdCtx, Pkey};
use crate::util::{cstring, string_at, take_string};
pub use crate::x509::Time;
use crate::x509::{Cert, CertStack, Store};

crate::handle!(
    /// An owned `OCSP_REQUEST`.
    OcspRequest, OCSP_REQUEST, OCSP_REQUEST_free
);
crate::handle!(
    /// An owned `OCSP_RESPONSE`.
    OcspResponse, OCSP_RESPONSE, OCSP_RESPONSE_free
);
crate::handle!(
    /// An owned `OCSP_BASICRESP`.
    BasicResp, OCSP_BASICRESP, OCSP_BASICRESP_free
);
crate::handle!(
    /// An owned `OCSP_CERTID`.
    CertId, OCSP_CERTID, OCSP_CERTID_free
);

/// The ASN.1 items `ocsp` and `cmp` read and write over HTTP.
#[derive(Clone, Copy)]
pub enum Item {
    OcspRequest,
    OcspResponse,
    CmpMsg,
}

impl Item {
    fn it(self) -> *const ASN1_ITEM {
        match self {
            // SAFETY: the item functions take no arguments and return static items.
            Item::OcspRequest => unsafe { ffi::OCSP_REQUEST_it() },
            // SAFETY: as above.
            Item::OcspResponse => unsafe { ffi::OCSP_RESPONSE_it() },
            // SAFETY: as above.
            Item::CmpMsg => unsafe { ffi::OSSL_CMP_MSG_it() },
        }
    }

    /// `ASN1_item_d2i_bio(it, bio, NULL)` (NULL `bio` allowed): the object, as a raw pointer
    /// of the item's type for the typed wrappers.
    pub(crate) fn d2i_bio(self, bio: *mut BIO) -> *mut c_void {
        // SAFETY: bio is NULL or live; the object is the caller's.
        unsafe { ffi::ASN1_item_d2i_bio(self.it(), bio, core::ptr::null_mut()) }
    }

    /// `ASN1_item_i2d_bio(it, out, obj)`.
    pub(crate) fn i2d_bio(self, out: &Bio, obj: *const c_void) -> c_int {
        // SAFETY: out is live; obj is a live object of the item's type.
        unsafe { ffi::ASN1_item_i2d_bio(self.it(), out.as_ptr(), obj) }
    }

    /// `ASN1_item_i2d(obj, NULL, it)`: the encoding's length.
    pub(crate) fn i2d_len(self, obj: *const c_void) -> c_int {
        // SAFETY: obj is a live object of the item's type; only the length is wanted.
        unsafe { ffi::ASN1_item_i2d(obj.cast(), core::ptr::null_mut(), self.it()) }
    }

    /// `ASN1_item_i2d_mem_bio(it, obj)`.
    pub(crate) fn i2d_mem_bio(self, obj: *const c_void) -> Option<Bio> {
        // SAFETY: obj is a live object of the item's type; the BIO is the caller's.
        Bio::from_ptr(unsafe { ffi::ASN1_item_i2d_mem_bio(self.it(), obj.cast()) })
    }
}

impl OcspRequest {
    /// `OCSP_REQUEST_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OCSP_REQUEST_new() })
    }

    /// `d2i_OCSP_REQUEST_bio(bio, NULL)`.
    pub fn read_der(bio: Option<&Bio>) -> Option<Self> {
        Self::from_ptr(
            Item::OcspRequest
                .d2i_bio(bio.map_or(core::ptr::null_mut(), Bio::as_ptr))
                .cast(),
        )
    }

    /// `i2d_OCSP_REQUEST_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        Item::OcspRequest.i2d_bio(out, self.as_ptr().cast())
    }

    /// The DER in a memory `BIO` (`ASN1_item_i2d_mem_bio`).
    pub fn to_mem_bio(&self) -> Option<Bio> {
        Item::OcspRequest.i2d_mem_bio(self.as_ptr().cast())
    }

    /// `OCSP_REQUEST_print(out, req, 0)`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_REQUEST_print(out.as_ptr(), self.as_ptr(), 0) }
    }

    /// `OCSP_request_add0_id(req, OCSP_CERTID_dup(id))`.
    pub fn add_id(&self, id: &CertId) -> bool {
        // SAFETY: id is live; the copy is owned here.
        let dup = unsafe { ffi::OCSP_CERTID_dup(id.as_ptr()) };
        if dup.is_null() {
            return false;
        }
        // SAFETY: both are live; on success the request takes the copy.
        if unsafe { ffi::OCSP_request_add0_id(self.as_ptr(), dup) }.is_null() {
            // SAFETY: dup is still owned here.
            unsafe { ffi::OCSP_CERTID_free(dup) };
            return false;
        }
        true
    }

    /// `OCSP_request_add1_nonce(req, NULL, -1)`.
    pub fn add1_nonce(&self) -> bool {
        // SAFETY: the request is live; a random nonce of the default length.
        unsafe { ffi::OCSP_request_add1_nonce(self.as_ptr(), core::ptr::null_mut(), -1) == 1 }
    }

    /// `OCSP_request_sign(req, signer, key, NULL, others, flags)`.
    pub fn sign(
        &self,
        signer: &Cert,
        key: &Pkey,
        others: Option<&CertStack>,
        flags: c_ulong,
    ) -> bool {
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe {
            ffi::OCSP_request_sign(
                self.as_ptr(),
                signer.as_ptr(),
                key.as_ptr(),
                core::ptr::null(),
                others.map_or(core::ptr::null_mut(), CertStack::as_ptr),
                flags,
            ) == 1
        }
    }

    /// The certificate IDs of its requests (`OCSP_onereq_get0_id` of each), copied.
    pub fn ids(&self) -> Vec<CertId> {
        // SAFETY: the request is live.
        let n = unsafe { ffi::OCSP_request_onereq_count(self.as_ptr()) };
        let mut out = Vec::new();
        for i in 0..n.max(0) {
            // SAFETY: i is in range; the entry is owned by the request.
            let one = unsafe { ffi::OCSP_request_onereq_get0(self.as_ptr(), i) };
            // SAFETY: one is live; the ID is owned by it.
            let id = unsafe { ffi::OCSP_onereq_get0_id(one) };
            // SAFETY: id is live; the copy is owned by the result.
            if let Some(c) = CertId::from_ptr(unsafe { ffi::OCSP_CERTID_dup(id) }) {
                out.push(c);
            }
        }
        out
    }

    /// `OCSP_request_onereq_count`.
    pub fn onereq_count(&self) -> c_int {
        // SAFETY: the request is live.
        unsafe { ffi::OCSP_request_onereq_count(self.as_ptr()) }
    }

    /// `OCSP_check_nonce(req, bs)`.
    pub fn check_nonce(&self, bs: &BasicResp) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_check_nonce(self.as_ptr(), bs.as_ptr()) }
    }
}

impl CertId {
    /// `OCSP_cert_to_id(md, subject, issuer)`.
    pub fn from_cert(md: Option<&Md>, subject: Option<&Cert>, issuer: &Cert) -> Option<Self> {
        // SAFETY: every pointer is live or NULL where allowed.
        Self::from_ptr(unsafe {
            ffi::OCSP_cert_to_id(
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
                subject.map_or(core::ptr::null(), |s| s.as_ptr().cast_const()),
                issuer.as_ptr(),
            )
        })
    }

    /// `add_ocsp_serial`'s ID: `OCSP_cert_id_new(md, subject name of issuer, its key, serial)`
    /// for the serial number `serial` (`s2i_ASN1_INTEGER`); `Err(true)` if the serial number
    /// doesn't convert.
    pub fn from_serial(md: &Md, issuer: &Cert, serial: &str) -> Result<Self, bool> {
        let s = cstring(serial).ok_or(true)?;
        // SAFETY: issuer is live; the name and key are owned by it.
        let iname = unsafe { ffi::X509_get_subject_name(issuer.as_ptr()) };
        // SAFETY: as above.
        let ikey = unsafe { ffi::X509_get0_pubkey_bitstr(issuer.as_ptr()) };
        // SAFETY: s is a C string; no method; the integer is the caller's.
        let sno = unsafe { ffi::s2i_ASN1_INTEGER(core::ptr::null_mut(), s.as_ptr()) };
        if sno.is_null() {
            return Err(true);
        }
        // SAFETY: every pointer is live.
        let id = unsafe { ffi::OCSP_cert_id_new(md.as_ptr(), iname, ikey, sno) };
        // SAFETY: sno is owned here.
        unsafe { ffi::ASN1_INTEGER_free(sno) };
        Self::from_ptr(id).ok_or(false)
    }

    /// The digest of its hash algorithm (`EVP_get_digestbyobj`).
    pub fn md(&self) -> Option<Md> {
        let mut obj = core::ptr::null_mut();
        // SAFETY: the ID is live; only the algorithm is wanted.
        unsafe {
            ffi::OCSP_id_get0_info(
                core::ptr::null_mut(),
                &mut obj,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                self.as_ptr(),
            )
        };
        // SAFETY: obj is NULL or live.
        let nid = unsafe { ffi::OBJ_obj2nid(obj) };
        // SAFETY: any NID; the name is static.
        let sn = string_at(unsafe { ffi::OBJ_nid2sn(nid) })?;
        Md::by_name(&sn)
    }

    /// `OCSP_id_issuer_cmp(self, other) == 0`.
    pub fn same_issuer(&self, other: &CertId) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_id_issuer_cmp(self.as_ptr(), other.as_ptr()) == 0 }
    }

    /// The serial number as `lookup_serial` of `ocsp.c` looks it up: "00" for zero, else
    /// `BN_bn2hex`.
    pub fn serial_hex(&self) -> Option<String> {
        let mut serial = core::ptr::null_mut();
        // SAFETY: the ID is live; only the serial number is wanted.
        unsafe {
            ffi::OCSP_id_get0_info(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut serial,
                self.as_ptr(),
            )
        };
        // SAFETY: serial is the ID's live integer; the number is owned here.
        let bn = unsafe { ffi::ASN1_INTEGER_to_BN(serial, core::ptr::null_mut()) };
        if bn.is_null() {
            return None;
        }
        // SAFETY: bn is live.
        let r = if unsafe { ffi::BN_is_zero(bn) } == 1 {
            Some("00".to_owned())
        } else {
            // SAFETY: bn is live; the string is the caller's.
            take_string(unsafe { ffi::BN_bn2hex(bn) })
        };
        // SAFETY: bn is owned here.
        unsafe { ffi::BN_free(bn) };
        r
    }
}

/// A time borrowed from a response.
#[derive(Clone, Copy)]
pub struct TimeRef<'a>(*mut ASN1_GENERALIZEDTIME, core::marker::PhantomData<&'a ()>);

impl TimeRef<'_> {
    /// `ASN1_GENERALIZEDTIME_print(out, t)`.
    pub fn print(self, out: &Bio) -> c_int {
        // SAFETY: both are live (the time is NULL or borrowed from its response).
        unsafe { ffi::ASN1_GENERALIZEDTIME_print(out.as_ptr(), self.0) }
    }

    fn ptr(t: Option<Self>) -> *mut ASN1_GENERALIZEDTIME {
        t.map_or(core::ptr::null_mut(), |t| t.0)
    }
}

/// A certificate's status in a response (`OCSP_resp_find_status`).
pub struct Status<'a> {
    pub status: c_int,
    pub reason: c_int,
    pub revtime: Option<TimeRef<'a>>,
    pub thisupd: Option<TimeRef<'a>>,
    pub nextupd: Option<TimeRef<'a>>,
}

/// `OCSP_check_validity(thisupd, nextupd, nsec, maxage)`.
pub fn check_validity(
    thisupd: Option<TimeRef<'_>>,
    nextupd: Option<TimeRef<'_>>,
    nsec: c_long,
    maxage: c_long,
) -> bool {
    // SAFETY: the times are NULL or live.
    unsafe {
        ffi::OCSP_check_validity(TimeRef::ptr(thisupd), TimeRef::ptr(nextupd), nsec, maxage) == 1
    }
}

fn time_ref<'a>(p: *mut ASN1_GENERALIZEDTIME) -> Option<TimeRef<'a>> {
    (!p.is_null()).then_some(TimeRef(p, core::marker::PhantomData))
}

impl BasicResp {
    /// `OCSP_BASICRESP_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OCSP_BASICRESP_new() })
    }

    /// `OCSP_resp_find_status(bs, id, ...)`.
    pub fn find_status(&self, id: &CertId) -> Option<Status<'_>> {
        let (mut status, mut reason) = (0, 0);
        let (mut rev, mut thisupd, mut nextupd) = (
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        // SAFETY: both are live; the times are borrowed from the response.
        let ok = unsafe {
            ffi::OCSP_resp_find_status(
                self.as_ptr(),
                id.as_ptr(),
                &mut status,
                &mut reason,
                &mut rev,
                &mut thisupd,
                &mut nextupd,
            )
        } == 1;
        ok.then(|| Status {
            status,
            reason,
            revtime: time_ref(rev),
            thisupd: time_ref(thisupd),
            nextupd: time_ref(nextupd),
        })
    }

    /// `OCSP_basic_verify(bs, certs, store, flags)`.
    pub fn verify(&self, certs: Option<&CertStack>, store: &Store, flags: c_ulong) -> c_int {
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe {
            ffi::OCSP_basic_verify(
                self.as_ptr(),
                certs.map_or(core::ptr::null_mut(), CertStack::as_ptr),
                store.as_ptr(),
                flags,
            )
        }
    }

    /// `OCSP_basic_add1_status(bs, cid, status, reason, revtime, thisupd, nextupd)`: the
    /// single response added, borrowed.
    pub fn add_status(
        &self,
        cid: &CertId,
        status: c_int,
        reason: c_int,
        revtime: Option<&Time>,
        thisupd: Option<&Time>,
        nextupd: Option<&Time>,
    ) -> Option<SingleResp<'_>> {
        let t = |t: Option<&Time>| t.map_or(core::ptr::null_mut(), Time::as_ptr);
        // SAFETY: every pointer is live or NULL where allowed; the result is owned by bs.
        let s = unsafe {
            ffi::OCSP_basic_add1_status(
                self.as_ptr(),
                cid.as_ptr(),
                status,
                reason,
                t(revtime),
                t(thisupd),
                t(nextupd),
            )
        };
        (!s.is_null()).then_some(SingleResp(s, core::marker::PhantomData))
    }

    /// `OCSP_copy_nonce(bs, req)`.
    pub fn copy_nonce(&self, req: &OcspRequest) {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_copy_nonce(self.as_ptr(), req.as_ptr()) };
    }

    /// `OCSP_basic_sign_ctx(bs, signer, ctx, certs, flags)`.
    pub fn sign_ctx(
        &self,
        signer: &Cert,
        ctx: &MdCtx,
        certs: Option<&CertStack>,
        flags: c_ulong,
    ) -> bool {
        // SAFETY: every pointer is live or NULL where allowed.
        unsafe {
            ffi::OCSP_basic_sign_ctx(
                self.as_ptr(),
                signer.as_ptr(),
                ctx.as_ptr(),
                certs.map_or(core::ptr::null_mut(), CertStack::as_ptr),
                flags,
            ) == 1
        }
    }

    /// `corrupt_signature(OCSP_resp_get0_signature(bs))` of `apps.c`: the signature's last
    /// byte flipped.
    pub fn corrupt_signature(&self) {
        // SAFETY: the response is live; the signature is owned by it.
        let sig = unsafe { ffi::OCSP_resp_get0_signature(self.as_ptr()) };
        if sig.is_null() {
            return;
        }
        // SAFETY: sig is live.
        let len = unsafe { ffi::ASN1_STRING_length(sig) };
        // SAFETY: as above; the data is the response's, which upstream writes in place too.
        let data = unsafe { ffi::ASN1_STRING_get0_data(sig) }.cast_mut();
        let Ok(last) = usize::try_from(len - 1) else {
            return;
        };
        if data.is_null() {
            return;
        }
        // SAFETY: last < len, inside the string's data.
        let p = unsafe { data.add(last) };
        // SAFETY: as above.
        unsafe { *p ^= 1 };
    }
}

/// A single response borrowed from its basic response.
pub struct SingleResp<'a>(*mut OCSP_SINGLERESP, core::marker::PhantomData<&'a ()>);

impl SingleResp<'_> {
    /// `OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date, t, 0, 0)`.
    pub fn add_invalidity_date(&self, t: &Time) {
        // SAFETY: both are live; the value is encoded (copied).
        unsafe {
            ffi::OCSP_SINGLERESP_add1_ext_i2d(self.0, NID_invalidity_date, t.as_ptr().cast(), 0, 0)
        };
    }

    /// `OCSP_SINGLERESP_add1_ext_i2d(single, NID_hold_instruction_code, obj, 0, 0)`.
    pub fn add_hold_instruction(&self, obj: &Object) {
        // SAFETY: as above.
        unsafe {
            ffi::OCSP_SINGLERESP_add1_ext_i2d(
                self.0,
                NID_hold_instruction_code,
                obj.as_ptr().cast(),
                0,
                0,
            )
        };
    }
}

impl Time {
    /// `X509_gmtime_adj(NULL, 0)`: now.
    pub fn now() -> Option<Self> {
        // SAFETY: a new time.
        Self::from_ptr(unsafe { ffi::X509_gmtime_adj(core::ptr::null_mut(), 0) })
    }

    /// `X509_time_adj_ex(NULL, days, secs, NULL)`.
    pub fn adj(days: c_int, secs: c_long) -> Option<Self> {
        // SAFETY: a new time, from now.
        Self::from_ptr(unsafe {
            ffi::X509_time_adj_ex(core::ptr::null_mut(), days, secs, core::ptr::null_mut())
        })
    }

    /// `ASN1_UTCTIME_new()` then `ASN1_UTCTIME_set_string(t, s)`: `Err(None)` when it can't
    /// be made, `Err(Some(t))` when the string is invalid (the time, still empty, is kept, as
    /// `unpack_revinfo` keeps it).
    pub fn utc_from_string_kept(s: &str) -> Result<Self, Option<Self>> {
        // SAFETY: no arguments.
        let t = Self::from_ptr(unsafe { ffi::ASN1_UTCTIME_new() }).ok_or(None)?;
        let Some(c) = cstring(s) else {
            return Err(Some(t));
        };
        // SAFETY: t is live; c is a C string.
        if unsafe { ffi::ASN1_UTCTIME_set_string(t.as_ptr(), c.as_ptr()) } != 1 {
            return Err(Some(t));
        }
        Ok(t)
    }
}

impl OcspResponse {
    /// `d2i_OCSP_RESPONSE_bio(bio, NULL)` (NULL `bio` allowed).
    pub fn read_der(bio: Option<&Bio>) -> Option<Self> {
        Self::from_ptr(
            Item::OcspResponse
                .d2i_bio(bio.map_or(core::ptr::null_mut(), Bio::as_ptr))
                .cast(),
        )
    }

    /// `i2d_OCSP_RESPONSE_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        Item::OcspResponse.i2d_bio(out, self.as_ptr().cast())
    }

    /// `OCSP_response_create(status, bs)`.
    pub fn create(status: c_int, bs: Option<&BasicResp>) -> Option<Self> {
        // SAFETY: bs is NULL or live (it is copied).
        Self::from_ptr(unsafe {
            ffi::OCSP_response_create(status, bs.map_or(core::ptr::null_mut(), BasicResp::as_ptr))
        })
    }

    /// `OCSP_response_status`.
    pub fn status(&self) -> c_int {
        // SAFETY: the response is live.
        unsafe { ffi::OCSP_response_status(self.as_ptr()) }
    }

    /// `OCSP_RESPONSE_print(out, resp, 0)`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_RESPONSE_print(out.as_ptr(), self.as_ptr(), 0) }
    }

    /// `OCSP_response_get1_basic`.
    pub fn basic(&self) -> Option<BasicResp> {
        // SAFETY: the response is live; the basic response is the caller's.
        BasicResp::from_ptr(unsafe { ffi::OCSP_response_get1_basic(self.as_ptr()) })
    }

    /// `ASN1_item_i2d(resp, NULL, OCSP_RESPONSE_it())`.
    pub fn der_len(&self) -> c_int {
        Item::OcspResponse.i2d_len(self.as_ptr().cast())
    }
}

/// `OCSP_response_status_str`.
pub fn response_status_str(s: c_long) -> String {
    // SAFETY: any value; the result is static.
    string_at(unsafe { ffi::OCSP_response_status_str(s) }).unwrap_or_default()
}

/// `OCSP_cert_status_str`.
pub fn cert_status_str(s: c_long) -> String {
    // SAFETY: as above.
    string_at(unsafe { ffi::OCSP_cert_status_str(s) }).unwrap_or_default()
}

/// `OCSP_crl_reason_str`.
pub fn crl_reason_str(s: c_long) -> String {
    // SAFETY: as above.
    string_at(unsafe { ffi::OCSP_crl_reason_str(s) }).unwrap_or_default()
}

/// One `name:value` key option on a key context (`pkey_ctrl_string` of `apps.c`).
fn pkey_ctrl_string(pctx: *mut crate::abi::EVP_PKEY_CTX, value: &str) -> c_int {
    let Some((k, v)) = value.split_once(':') else {
        return 0;
    };
    let (Some(k), Some(v)) = (cstring(k), cstring(v)) else {
        return 0;
    };
    // SAFETY: pctx is a live context; the strings are valid.
    unsafe { ffi::EVP_PKEY_CTX_ctrl_str(pctx, k.as_ptr(), v.as_ptr()) }
}

impl MdCtx {
    /// `EVP_DigestSignInit(ctx, &pctx, md, NULL, key)` then each `name:value` option on the
    /// key context: `Err(None)` if the initialization fails, `Err(Some(option))` for an
    /// option that does.
    pub fn sign_init_with(
        &self,
        md: Option<&Md>,
        key: &Pkey,
        opts: &[String],
    ) -> Result<(), Option<String>> {
        let mut pctx = core::ptr::null_mut();
        // SAFETY: every pointer is live or NULL where allowed; the key context is owned by
        // the digest context.
        let r = unsafe {
            ffi::EVP_DigestSignInit(
                self.as_ptr(),
                &mut pctx,
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
                core::ptr::null_mut(),
                key.as_ptr(),
            )
        };
        if r != 1 {
            return Err(None);
        }
        for o in opts {
            if pkey_ctrl_string(pctx, o) <= 0 {
                return Err(Some(o.clone()));
            }
        }
        Ok(())
    }
}
