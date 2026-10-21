//! Time stamps (RFC 3161: `TS_REQ`, `TS_RESP`, the responder's configuration, and
//! verification), for `ts`.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::abi::{
    ASN1_INTEGER, TS_INFO_ADD_INFO_NOT_AVAILABLE, TS_RESP_CTX, TS_STATUS_GRANTED,
    TS_STATUS_REJECTION, V_ASN1_NULL, X509_STORE_CTX,
};
use crate::bio::Bio;
use crate::conf::Conf;
use crate::evp::Md;
use crate::ffi;
use crate::object::Object;
use crate::pkcs7::Pkcs7;
use crate::util::{cstring, string_at};
use crate::x509::{CertStack, Store};

crate::handle!(
    /// An owned `TS_REQ`.
    TsReq, TS_REQ, TS_REQ_free
);
crate::handle!(
    /// An owned `TS_RESP`.
    TsResp, TS_RESP, TS_RESP_free
);
crate::handle!(
    /// An owned `TS_VERIFY_CTX`.
    TsVerifyCtx, TS_VERIFY_CTX, TS_VERIFY_CTX_free
);

/// `EVP_MD_get_size(md)`.
pub fn md_size(md: &Md) -> c_int {
    // SAFETY: the digest is live.
    unsafe { ffi::EVP_MD_get_size(md.as_ptr()) }
}

/// The digest of everything `input` holds (`create_digest` of `ts.c`): `None` on failure.
pub fn digest_bio(md: &Md, input: &Bio) -> Option<Vec<u8>> {
    let size = usize::try_from(md_size(md)).ok()?;
    // SAFETY: no arguments.
    let ctx = unsafe { ffi::EVP_MD_CTX_new() };
    if ctx.is_null() {
        return None;
    }
    let mut out = vec![0u8; size.max(64)];
    let r = (|| {
        // SAFETY: ctx and md are live.
        if unsafe { ffi::EVP_DigestInit(ctx, md.as_ptr()) } != 1 {
            return None;
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = input.read(&mut buf);
            let Ok(n) = usize::try_from(n) else {
                break;
            };
            if n == 0 {
                break;
            }
            // SAFETY: ctx is initialized; buf holds n bytes.
            if unsafe { ffi::EVP_DigestUpdate(ctx, buf.as_ptr().cast(), n) } != 1 {
                return None;
            }
        }
        // SAFETY: out is writable for the digest's size (or more).
        if unsafe { ffi::EVP_DigestFinal(ctx, out.as_mut_ptr(), core::ptr::null_mut()) } != 1 {
            return None;
        }
        out.truncate(size);
        Some(out)
    })();
    // SAFETY: ctx is owned here.
    unsafe { ffi::EVP_MD_CTX_free(ctx) };
    r
}

/// `RAND_bytes(buf, n)`: `None` on failure.
pub fn rand_bytes(n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let len = c_int::try_from(n).ok()?;
    // SAFETY: buf is writable for len bytes.
    (unsafe { ffi::RAND_bytes(buf.as_mut_ptr(), len) } > 0).then_some(buf)
}

/// A positive `ASN1_INTEGER` holding `magnitude` as its content octets.
fn integer_of(magnitude: &[u8]) -> Option<*mut ASN1_INTEGER> {
    // SAFETY: no arguments.
    let i = unsafe { ffi::ASN1_INTEGER_new() };
    if i.is_null() {
        return None;
    }
    let len = c_int::try_from(magnitude.len()).ok()?;
    // SAFETY: i is live; magnitude is valid for len bytes (copied).
    if unsafe { ffi::ASN1_STRING_set(i, magnitude.as_ptr().cast(), len) } != 1 {
        // SAFETY: i is owned here.
        unsafe { ffi::ASN1_INTEGER_free(i) };
        return None;
    }
    Some(i)
}

impl TsReq {
    /// `d2i_TS_REQ_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_TS_REQ_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `i2d_TS_REQ_bio`.
    pub fn write_der(&self, out: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::i2d_TS_REQ_bio(out.as_ptr(), self.as_ptr()) == 1 }
    }

    /// `TS_REQ_print_bio`.
    pub fn print(&self, out: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::TS_REQ_print_bio(out.as_ptr(), self.as_ptr()) == 1 }
    }

    /// The request `create_query` of `ts.c` builds: version 1, the imprint (the digest's
    /// algorithm, with NULL parameters), the policy, the nonce (its content octets), and
    /// whether the TSA's certificate is wanted. `None` if a step fails.
    pub fn create(
        md: &Md,
        imprint: &[u8],
        policy: Option<&Object>,
        nonce: Option<&[u8]>,
        cert_req: bool,
    ) -> Option<Self> {
        // SAFETY: no arguments.
        let req = Self::from_ptr(unsafe { ffi::TS_REQ_new() })?;
        // SAFETY: the request is live.
        if unsafe { ffi::TS_REQ_set_version(req.as_ptr(), 1) } != 1 {
            return None;
        }
        // SAFETY: no arguments.
        let mi = unsafe { ffi::TS_MSG_IMPRINT_new() };
        // SAFETY: no arguments.
        let algo = unsafe { ffi::X509_ALGOR_new() };
        let ok = (|| {
            if mi.is_null() || algo.is_null() {
                return None;
            }
            // SAFETY: the digest is live.
            let nid = unsafe { ffi::EVP_MD_get_type(md.as_ptr()) };
            // SAFETY: any NID is accepted; the object is static or new.
            let obj = unsafe { ffi::OBJ_nid2obj(nid) };
            if obj.is_null() {
                return None;
            }
            // SAFETY: no arguments.
            let param = unsafe { ffi::ASN1_TYPE_new() };
            if param.is_null() {
                return None;
            }
            // SAFETY: param is a fresh ASN1_TYPE (public layout); NULL takes no value.
            unsafe { (*param).type_ = V_ASN1_NULL };
            // SAFETY: algo is a fresh X509_ALGOR (public layout); it takes obj and param.
            unsafe { (*algo).algorithm = obj };
            // SAFETY: as above.
            unsafe { (*algo).parameter = param };
            // SAFETY: both are live; the imprint copies the algorithm.
            if unsafe { ffi::TS_MSG_IMPRINT_set_algo(mi, algo) } != 1 {
                return None;
            }
            let len = c_int::try_from(imprint.len()).ok()?;
            // SAFETY: mi is live; the digest is valid for len bytes (copied).
            if unsafe { ffi::TS_MSG_IMPRINT_set_msg(mi, imprint.as_ptr().cast_mut(), len) } != 1 {
                return None;
            }
            // SAFETY: both are live; the request copies the imprint.
            if unsafe { ffi::TS_REQ_set_msg_imprint(req.as_ptr(), mi) } != 1 {
                return None;
            }
            if let Some(p) = policy {
                // SAFETY: both are live; the request copies the policy.
                if unsafe { ffi::TS_REQ_set_policy_id(req.as_ptr(), p.as_ptr()) } != 1 {
                    return None;
                }
            }
            if let Some(n) = nonce {
                let i = integer_of(n)?;
                // SAFETY: both are live; the request copies the nonce.
                let r = unsafe { ffi::TS_REQ_set_nonce(req.as_ptr(), i) };
                // SAFETY: i is owned here.
                unsafe { ffi::ASN1_INTEGER_free(i) };
                if r != 1 {
                    return None;
                }
            }
            // SAFETY: the request is live.
            if unsafe { ffi::TS_REQ_set_cert_req(req.as_ptr(), c_int::from(cert_req)) } != 1 {
                return None;
            }
            Some(())
        })();
        // SAFETY: both are NULL or owned here.
        unsafe { ffi::TS_MSG_IMPRINT_free(mi) };
        // SAFETY: as above.
        unsafe { ffi::X509_ALGOR_free(algo) };
        ok.map(|()| req)
    }
}

/// The serial file's next number: `next_serial` of `ts.c` (messages to standard error).
fn next_serial(err: &Bio, serialfile: &str) -> Option<*mut ASN1_INTEGER> {
    // SAFETY: no arguments.
    let serial = unsafe { ffi::ASN1_INTEGER_new() };
    if serial.is_null() {
        return None;
    }
    let Some(input) = Bio::new_file(serialfile, "r") else {
        crate::err::clear();
        let _ = err.write_all(
            format!(
                "Warning: could not open file {serialfile} for reading, using serial number: 1\n"
            )
            .as_bytes(),
        );
        // SAFETY: serial is live.
        if unsafe { ffi::ASN1_INTEGER_set(serial, 1) } != 1 {
            // SAFETY: serial is owned here.
            unsafe { ffi::ASN1_INTEGER_free(serial) };
            return None;
        }
        return Some(serial);
    };
    let mut buf = [0 as c_char; 1024];
    let size = c_int::try_from(buf.len()).unwrap_or(0);
    // SAFETY: input and serial are live; buf is writable for size bytes.
    if unsafe { ffi::a2i_ASN1_INTEGER(input.as_ptr(), serial, buf.as_mut_ptr(), size) } != 1 {
        let _ = err.write_all(format!("unable to load number from {serialfile}\n").as_bytes());
        // SAFETY: serial is owned here.
        unsafe { ffi::ASN1_INTEGER_free(serial) };
        return None;
    }
    // SAFETY: serial is live; the number is the caller's.
    let bn = unsafe { ffi::ASN1_INTEGER_to_BN(serial, core::ptr::null_mut()) };
    // SAFETY: serial is owned here.
    unsafe { ffi::ASN1_INTEGER_free(serial) };
    if bn.is_null() {
        return None;
    }
    // SAFETY: bn is live.
    let next = if unsafe { ffi::BN_add_word(bn, 1) } == 1 {
        // SAFETY: bn is live; the integer is the caller's.
        unsafe { ffi::BN_to_ASN1_INTEGER(bn, core::ptr::null_mut()) }
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: bn is owned here.
    unsafe { ffi::BN_free(bn) };
    (!next.is_null()).then_some(next)
}

/// `save_ts_serial`.
fn save_ts_serial(err: &Bio, serialfile: &str, serial: *mut ASN1_INTEGER) {
    let ok = Bio::new_file(serialfile, "w").is_some_and(|out| {
        // SAFETY: both are live.
        (unsafe { ffi::i2a_ASN1_INTEGER(out.as_ptr(), serial) }) > 0 && out.write(b"\n") > 0
    });
    if !ok {
        let _ = err.write_all(format!("could not save serial number to {serialfile}\n").as_bytes());
    }
}

/// `serial_cb` of `ts.c`: the next serial number from the file `data` names, saved back.
unsafe extern "C" fn serial_cb(ctx: *mut TS_RESP_CTX, data: *mut c_void) -> *mut ASN1_INTEGER {
    let Some(err) = Bio::new_fd(2, false) else {
        return core::ptr::null_mut();
    };
    let file = string_at(data.cast()).unwrap_or_default();
    match next_serial(&err, &file) {
        None => {
            // SAFETY: ctx is the live context the library calls back with.
            unsafe {
                ffi::TS_RESP_CTX_set_status_info(
                    ctx,
                    TS_STATUS_REJECTION,
                    c"Error during serial number generation.".as_ptr(),
                )
            };
            // SAFETY: as above.
            unsafe { ffi::TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE) };
            core::ptr::null_mut()
        }
        Some(serial) => {
            save_ts_serial(&err, &file, serial);
            serial
        }
    }
}

/// The inputs of `create_response` of `ts.c` (each `None` is C's NULL).
pub struct ResponseInputs<'a> {
    pub section: Option<&'a str>,
    pub engine: Option<&'a str>,
    pub queryfile: Option<&'a str>,
    pub passin: Option<&'a str>,
    pub inkey: Option<&'a str>,
    pub md: Option<&'a Md>,
    pub signer: Option<&'a str>,
    pub chain: Option<&'a str>,
    pub policy: Option<&'a str>,
}

/// An optional C string: `Err` if it holds a NUL.
fn opt_c(s: Option<&str>) -> Result<Option<std::ffi::CString>, ()> {
    s.map(|s| cstring(s).ok_or(())).transpose()
}

fn ptr_of(c: &Option<std::ffi::CString>) -> *const c_char {
    c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

impl TsResp {
    /// `d2i_TS_RESP_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_TS_RESP_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `read_PKCS7` of `ts.c`: a token, with a granted status.
    pub fn read_token(bio: &Bio) -> Option<Self> {
        let token = Pkcs7::read_der(bio)?;
        // SAFETY: the token is live; the info is the caller's.
        let tst = unsafe { ffi::PKCS7_to_TS_TST_INFO(token.as_ptr()) };
        if tst.is_null() {
            return None;
        }
        // SAFETY: no arguments.
        let resp = Self::from_ptr(unsafe { ffi::TS_RESP_new() });
        // SAFETY: no arguments.
        let si = unsafe { ffi::TS_STATUS_INFO_new() };
        let ok = (|| {
            let resp = resp.as_ref()?;
            if si.is_null() {
                return None;
            }
            // SAFETY: si is live.
            if unsafe { ffi::TS_STATUS_INFO_set_status(si, TS_STATUS_GRANTED) } != 1 {
                return None;
            }
            // SAFETY: both are live; the response copies the status.
            if unsafe { ffi::TS_RESP_set_status_info(resp.as_ptr(), si) } != 1 {
                return None;
            }
            Some(())
        })();
        // SAFETY: si is NULL or owned here.
        unsafe { ffi::TS_STATUS_INFO_free(si) };
        let (Some(()), Some(resp)) = (ok, resp) else {
            // SAFETY: tst is owned here.
            unsafe { ffi::TS_TST_INFO_free(tst) };
            return None;
        };
        // SAFETY: all are live; the response takes the token and the info.
        unsafe { ffi::TS_RESP_set_tst_info(resp.as_ptr(), token.into_ptr(), tst) };
        Some(resp)
    }

    /// `create_response` of `ts.c`: the responder configured from `conf`'s TSA section,
    /// answering the query in `queryfile`.
    pub fn create(conf: &Conf, i: &ResponseInputs<'_>) -> Option<Self> {
        let query_bio = Bio::new_file(i.queryfile?, "rb")?;
        let (section, engine) = (opt_c(i.section).ok()?, opt_c(i.engine).ok()?);
        let (signer, chain) = (opt_c(i.signer).ok()?, opt_c(i.chain).ok()?);
        let (inkey, passin) = (opt_c(i.inkey).ok()?, opt_c(i.passin).ok()?);
        let policy = opt_c(i.policy).ok()?;
        let c = conf.as_ptr();
        // SAFETY: the configuration is live; section NULL or a C string.
        let section = unsafe { ffi::TS_CONF_get_tsa_section(c, ptr_of(&section)) };
        if section.is_null() {
            return None;
        }
        // SAFETY: no arguments.
        let ctx = unsafe { ffi::TS_RESP_CTX_new() };
        if ctx.is_null() {
            return None;
        }
        let r = (|| {
            // Each call: the configuration and the context are live, the strings NULL or C
            // strings, and section the configuration's own.
            // SAFETY: as above; the callback is a static function.
            if unsafe { ffi::TS_CONF_set_serial(c, section, Some(serial_cb), ctx) } != 1 {
                return None;
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_crypto_device(c, section, ptr_of(&engine)) } != 1 {
                return None;
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_signer_cert(c, section, ptr_of(&signer), ctx) } != 1 {
                return None;
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_certs(c, section, ptr_of(&chain), ctx) } != 1 {
                return None;
            }
            // SAFETY: as above.
            if unsafe {
                ffi::TS_CONF_set_signer_key(c, section, ptr_of(&inkey), ptr_of(&passin), ctx)
            } != 1
            {
                return None;
            }
            if let Some(md) = i.md {
                // SAFETY: as above; md is live.
                if unsafe { ffi::TS_RESP_CTX_set_signer_digest(ctx, md.as_ptr()) } != 1 {
                    return None;
                }
            } else {
                // SAFETY: as above.
                if unsafe { ffi::TS_CONF_set_signer_digest(c, section, core::ptr::null(), ctx) }
                    != 1
                {
                    return None;
                }
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_ess_cert_id_digest(c, section, ctx) } != 1 {
                return None;
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_def_policy(c, section, ptr_of(&policy), ctx) } != 1 {
                return None;
            }
            type Set = unsafe fn(*mut crate::abi::CONF, *const c_char, *mut TS_RESP_CTX) -> c_int;
            let rest: [Set; 6] = [
                ffi::TS_CONF_set_policies,
                ffi::TS_CONF_set_digests,
                ffi::TS_CONF_set_accuracy,
                |c, s, x| {
                    // SAFETY: the caller's (the loop's) guarantee.
                    unsafe { ffi::TS_CONF_set_clock_precision_digits(c, s, x) }
                },
                ffi::TS_CONF_set_ordering,
                ffi::TS_CONF_set_tsa_name,
            ];
            for f in rest {
                // SAFETY: as above.
                if unsafe { f(c, section, ctx) } != 1 {
                    return None;
                }
            }
            // SAFETY: as above.
            if unsafe { ffi::TS_CONF_set_ess_cert_id_chain(c, section, ctx) } != 1 {
                return None;
            }
            // SAFETY: the context and the BIO are live; the response is the caller's.
            Self::from_ptr(unsafe { ffi::TS_RESP_create_response(ctx, query_bio.as_ptr()) })
        })();
        // SAFETY: ctx is owned here.
        unsafe { ffi::TS_RESP_CTX_free(ctx) };
        r
    }

    /// `i2d_TS_RESP_bio`.
    pub fn write_der(&self, out: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::i2d_TS_RESP_bio(out.as_ptr(), self.as_ptr()) == 1 }
    }

    /// `i2d_PKCS7_bio(out, TS_RESP_get_token(resp))`.
    pub fn write_token_der(&self, out: &Bio) -> bool {
        // SAFETY: the response is live; the token is owned by it (NULL allowed).
        let token = unsafe { ffi::TS_RESP_get_token(self.as_ptr()) };
        // SAFETY: as above.
        unsafe { ffi::i2d_PKCS7_bio(out.as_ptr(), token) == 1 }
    }

    /// `TS_RESP_print_bio`.
    pub fn print(&self, out: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::TS_RESP_print_bio(out.as_ptr(), self.as_ptr()) == 1 }
    }

    /// `TS_TST_INFO_print_bio(out, TS_RESP_get_tst_info(resp))`.
    pub fn print_tst_info(&self, out: &Bio) -> bool {
        // SAFETY: the response is live; the info is owned by it (NULL allowed).
        let tst = unsafe { ffi::TS_RESP_get_tst_info(self.as_ptr()) };
        // SAFETY: as above.
        unsafe { ffi::TS_TST_INFO_print_bio(out.as_ptr(), tst) == 1 }
    }
}

impl TsVerifyCtx {
    /// `TS_VERIFY_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::TS_VERIFY_CTX_new() })
    }

    /// `TS_REQ_to_TS_VERIFY_CTX(req, NULL)`.
    pub fn from_req(req: &TsReq) -> Option<Self> {
        // SAFETY: the request is live.
        Self::from_ptr(unsafe { ffi::TS_REQ_to_TS_VERIFY_CTX(req.as_ptr(), core::ptr::null_mut()) })
    }

    /// `TS_VERIFY_CTX_set0_data(ctx, bio)` (which takes the BIO).
    pub fn set0_data(&self, data: Bio) -> bool {
        let p = data.into_ptr();
        // SAFETY: both are live; on success the context owns the BIO.
        if unsafe { ffi::TS_VERIFY_CTX_set0_data(self.as_ptr(), p) } == 1 {
            return true;
        }
        drop(Bio::from_ptr(p));
        false
    }

    /// `TS_VERIFY_CTX_set0_imprint(ctx, OPENSSL_hexstr2buf(digest, &len), len)`.
    pub fn set0_imprint_hex(&self, digest: &str) -> bool {
        let Some(c) = cstring(digest) else {
            return false;
        };
        let mut len: c_long = 0;
        // SAFETY: c is a C string; the buffer is the caller's (NULL on failure).
        let buf = unsafe { ffi::OPENSSL_hexstr2buf(c.as_ptr(), &mut len) };
        // SAFETY: the context is live; it takes buf (NULL allowed).
        unsafe { ffi::TS_VERIFY_CTX_set0_imprint(self.as_ptr(), buf, len) == 1 }
    }

    /// `TS_VERIFY_CTX_add_flags`.
    pub fn add_flags(&self, flags: c_int) {
        // SAFETY: the context is live.
        unsafe { ffi::TS_VERIFY_CTX_add_flags(self.as_ptr(), flags) };
    }

    /// `TS_VERIFY_CTX_set0_store(ctx, store)` (which takes it; `None` is NULL).
    pub fn set0_store(&self, store: Option<Store>) -> bool {
        let p = store.map_or(core::ptr::null_mut(), Store::into_ptr);
        // SAFETY: the context is live; it takes the store (NULL allowed).
        unsafe { ffi::TS_VERIFY_CTX_set0_store(self.as_ptr(), p) == 1 }
    }

    /// `TS_VERIFY_CTX_set0_certs(ctx, certs)` (which takes them).
    pub fn set0_certs(&self, certs: CertStack) -> bool {
        let p = certs.into_ptr();
        // SAFETY: both are live; the context takes the stack.
        unsafe { ffi::TS_VERIFY_CTX_set0_certs(self.as_ptr(), p) == 1 }
    }

    /// `TS_RESP_verify_response`.
    pub fn verify_response(&self, resp: &TsResp) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::TS_RESP_verify_response(self.as_ptr(), resp.as_ptr()) == 1 }
    }

    /// `TS_RESP_verify_token`.
    pub fn verify_token(&self, token: &Pkcs7) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::TS_RESP_verify_token(self.as_ptr(), token.as_ptr()) == 1 }
    }
}

/// `verify_cb` of `ts.c`: the verification's own verdict.
unsafe extern "C" fn verify_cb(ok: c_int, _ctx: *mut X509_STORE_CTX) -> c_int {
    ok
}

impl Store {
    /// `X509_STORE_set_verify_cb(store, verify_cb)` with `ts`'s callback, which returns the
    /// verdict unchanged.
    pub fn set_passthrough_verify_cb(&self) {
        // SAFETY: the store is live; the callback is a static function.
        unsafe { ffi::X509_STORE_set_verify_cb(self.as_ptr(), Some(verify_cb)) };
    }
}

/// `OBJ_create_objects(bio)`.
pub fn create_objects(bio: &Bio) -> c_int {
    // SAFETY: the BIO is live.
    unsafe { ffi::OBJ_create_objects(bio.as_ptr()) }
}
