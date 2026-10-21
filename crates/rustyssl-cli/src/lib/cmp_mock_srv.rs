//! The CMP mock server (`apps/lib/cmp_mock_srv.c`): the request handlers `openssl cmp` uses
//! for `-use_mock_srv` and `-port`. It answers with what it was given (a certificate, its
//! chain, CA certificates, a CRL, root CA key update certificates, a status), optionally after
//! polling, and checks what it's given to check (the reference certificate, the certificate
//! hash in a certConf).
//!
//! `ossl_cmp_mock_srv_set_useBadProtection` and `ossl_cmp_mock_server_perform` aren't here:
//! `cmp.c` uses neither (only upstream's unit tests do).

use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Rc;

use rustyssl_ossl::abi::{
    ASN1_STRFLGS_ESC_QUOTE, CMP_R_CERTHASH_UNMATCHED, CMP_R_ERROR_PROCESSING_MESSAGE,
    CMP_R_INVALID_ARGS, CMP_R_MISSING_CERTID, CMP_R_NULL_ARGUMENT, CMP_R_REQUEST_NOT_ACCEPTED,
    CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED, CMP_R_UNEXPECTED_CERTPROFILE,
    CMP_R_UNEXPECTED_CRLSTATUSLIST, CMP_R_UNEXPECTED_POLLREQ, CMP_R_UNKNOWN_CRL_ISSUER,
    CMP_R_WRONG_CERTID, ERR_R_PASSED_INVALID_ARGUMENT, NID_X9_62_id_ecPublicKey, NID_id_it_caCerts,
    NID_id_it_certProfile, NID_id_it_certReqTemplate, NID_id_it_crlStatusList,
    NID_id_it_rootCaCert, OSSL_CMP_CR, OSSL_CMP_ERROR, OSSL_CMP_IR, OSSL_CMP_KUR, OSSL_CMP_P10CR,
    OSSL_CMP_PKISTATUS_waiting,
};
use rustyssl_ossl::cmp::{
    self, Atav, Atavs, CertResponse, CertTemplate, CrlIssuer, CrlStatusRef, CrmfMsgRef,
    FreeTextRef, IntegerRef, Itav, ItavRef, ItavStack, MsgRef, Pkisi, PkisiRef, Poll, ReqRef,
    Server, SrvCtx, SrvRef,
};
use rustyssl_ossl::pkey::Pkey;
use rustyssl_ossl::provider::LibCtx;
use rustyssl_ossl::x509::{Cert, CertStack, Crl, NameRef};

use crate::lib::io;
use crate::lib::opt::eprintf;

/// The mock server's state (`mock_srv_ctx`).
struct State {
    /// The certificate to expect in the oldCertID of a kur and in an rr.
    ref_cert: Option<Cert>,
    /// The certificate to return in an ip/cp/kup.
    cert_out: Option<Cert>,
    /// The private key to return for central key generation.
    key_out: Option<Pkey>,
    /// The CRL to return in a genp for crls.
    crl_out: Option<Crl>,
    /// The chain of `cert_out`, for the extraCerts.
    chain_out: Option<CertStack>,
    /// The caPubs of an ip and the caCerts of a genp.
    ca_pubs_out: Option<CertStack>,
    new_with_new: Option<Cert>,
    new_with_old: Option<Cert>,
    old_with_new: Option<Cert>,
    /// The status of an ip/cp/kup/rp unless polling.
    status_out: Option<Pkisi>,
    /// Answer requests of this body type (1: all) with an error.
    send_error: i32,
    /// The original request while polling.
    req: Option<rustyssl_ossl::cmp::Msg>,
    /// Polls before the actual response.
    poll_count: i32,
    /// Polls so far for the current request.
    curr_poll_count: i32,
    /// The time the client should wait between polls.
    check_after_time: i32,
}

/// `ERR_raise(ERR_LIB_CMP, reason)` at `line` of `cmp_mock_srv.c` in `func`.
fn raise(reason: i32, line: i32, func: &'static CStr) {
    cmp::raise(reason, c"apps/lib/cmp_mock_srv.c", line, func, None);
}

/// The server context with the mock server's handlers, and the handle that configures them.
pub struct MockSrv {
    srv: SrvCtx,
    state: Rc<RefCell<State>>,
}

struct Handler(Rc<RefCell<State>>);

/// `ossl_cmp_mock_srv_new(libctx, propq)`.
pub fn mock_srv_new(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<MockSrv> {
    let state = Rc::new(RefCell::new(State {
        ref_cert: None,
        cert_out: None,
        key_out: None,
        crl_out: None,
        chain_out: None,
        ca_pubs_out: None,
        new_with_new: None,
        new_with_old: None,
        old_with_new: None,
        status_out: Some(Pkisi::new()?),
        send_error: -1,
        req: None,
        poll_count: 0,
        curr_poll_count: 0,
        check_after_time: 0,
    }));
    let srv = SrvCtx::new(libctx, propq, Box::new(Handler(Rc::clone(&state))))?;
    Some(MockSrv { srv, state })
}

impl MockSrv {
    /// The server context.
    pub fn srv(&self) -> &SrvCtx {
        &self.srv
    }

    /// The server context, for the client context to keep.
    pub fn into_srv(self) -> SrvCtx {
        self.srv
    }

    /// `ossl_cmp_mock_srv_set1_refCert`.
    pub fn set1_ref_cert(&self, cert: Option<&Cert>) -> bool {
        self.state.borrow_mut().ref_cert = cert.map(Cert::clone_ref);
        true
    }

    /// `ossl_cmp_mock_srv_set1_certOut`.
    pub fn set1_cert_out(&self, cert: Option<&Cert>) -> bool {
        self.state.borrow_mut().cert_out = cert.map(Cert::clone_ref);
        true
    }

    /// `ossl_cmp_mock_srv_set1_keyOut`.
    pub fn set1_key_out(&self, pkey: &Pkey) -> bool {
        let Some(k) = pkey.clone_ref() else {
            return false;
        };
        self.state.borrow_mut().key_out = Some(k);
        true
    }

    /// `ossl_cmp_mock_srv_set1_crlOut`.
    pub fn set1_crl_out(&self, crl: &Crl) -> bool {
        let Some(c) = crl.clone_ref() else {
            return false;
        };
        self.state.borrow_mut().crl_out = Some(c);
        true
    }

    /// `ossl_cmp_mock_srv_set1_chainOut`.
    pub fn set1_chain_out(&self, chain: &CertStack) -> bool {
        let Some(c) = chain.up_ref_copy() else {
            return false;
        };
        self.state.borrow_mut().chain_out = Some(c);
        true
    }

    /// `ossl_cmp_mock_srv_set1_caPubsOut`.
    pub fn set1_ca_pubs_out(&self, ca_pubs: &CertStack) -> bool {
        let Some(c) = ca_pubs.up_ref_copy() else {
            return false;
        };
        self.state.borrow_mut().ca_pubs_out = Some(c);
        true
    }

    /// `ossl_cmp_mock_srv_set1_newWithNew`.
    pub fn set1_new_with_new(&self, cert: Option<&Cert>) -> bool {
        self.state.borrow_mut().new_with_new = cert.map(Cert::clone_ref);
        true
    }

    /// `ossl_cmp_mock_srv_set1_newWithOld`.
    pub fn set1_new_with_old(&self, cert: Option<&Cert>) -> bool {
        self.state.borrow_mut().new_with_old = cert.map(Cert::clone_ref);
        true
    }

    /// `ossl_cmp_mock_srv_set1_oldWithNew`.
    pub fn set1_old_with_new(&self, cert: Option<&Cert>) -> bool {
        self.state.borrow_mut().old_with_new = cert.map(Cert::clone_ref);
        true
    }

    /// `ossl_cmp_mock_srv_set_statusInfo`.
    pub fn set_status_info(&self, status: i32, fail_info: i32, text: Option<&str>) -> bool {
        let Some(si) = Pkisi::status_info(status, fail_info, text) else {
            return false;
        };
        self.state.borrow_mut().status_out = Some(si);
        true
    }

    /// `ossl_cmp_mock_srv_set_sendError`.
    pub fn set_send_error(&self, bodytype: i32) -> bool {
        self.state.borrow_mut().send_error = bodytype;
        true
    }

    /// `ossl_cmp_mock_srv_set_pollCount`.
    pub fn set_poll_count(&self, count: i32) -> bool {
        if count < 0 {
            raise(CMP_R_INVALID_ARGS, 215, c"ossl_cmp_mock_srv_set_pollCount");
            return false;
        }
        self.state.borrow_mut().poll_count = count;
        true
    }

    /// `ossl_cmp_mock_srv_set_checkAfterTime`.
    pub fn set_check_after_time(&self, sec: i32) -> bool {
        self.state.borrow_mut().check_after_time = sec;
        true
    }
}

/// `refcert_cmp`: whether the issuer and serial number match the reference certificate, as
/// far as it is given.
fn refcert_cmp(
    refcert: Option<&Cert>,
    issuer: Option<NameRef<'_>>,
    serial: Option<&IntegerRef>,
) -> bool {
    let Some(r) = refcert else {
        return true;
    };
    let issuer_ok = match issuer {
        Some(i) => cmp::name_cmp(i, r.issuer_name()) == 0,
        None => false,
    };
    let serial_ok = match (r.serial_ref(), serial) {
        (None, _) => true,
        (Some(rs), Some(s)) => s.compare(rs) == 0,
        (Some(_), None) => false,
    };
    issuer_ok && serial_ok
}

/// `check_client_crl`: -1 for error, 0 for no update available, 1 for an update.
fn check_client_crl(list: &[Option<&CrlStatusRef>], crl: Option<&Crl>) -> i32 {
    if list.len() != 1 {
        raise(CMP_R_UNEXPECTED_CRLSTATUSLIST, 470, c"check_client_crl");
        return -1;
    }
    let Some(crl) = crl else {
        return 0;
    };
    let Some(Some(status)) = list.first() else {
        return -1;
    };
    let Some((issuer, thisupd)) = status.issuer_and_update(crl) else {
        return -1;
    };
    match issuer {
        CrlIssuer::Absent => {}
        CrlIssuer::DirName(n) => {
            if cmp::name_cmp(n, crl.issuer_name()) != 0 {
                raise(CMP_R_UNKNOWN_CRL_ISSUER, 487, c"check_client_crl");
                return -1;
            }
        }
        CrlIssuer::Other => {
            raise(
                CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED,
                491,
                c"check_client_crl",
            );
            return -1;
        }
    }
    i32::from(thisupd.is_none_or(|c| c < 0))
}

impl Handler {
    /// `process_genm_itav`.
    fn genm_itav(&self, nid: i32, req: &ItavRef) -> Option<Itav> {
        let st = self.0.borrow();
        match nid {
            n if n == NID_id_it_caCerts => Itav::new_ca_certs(st.ca_pubs_out.as_ref()),
            n if n == NID_id_it_rootCaCert => {
                let rootcacert = req.root_ca_cert()?;
                let mismatch = rootcacert.is_some_and(|r| match &st.new_with_new {
                    Some(n) => cmp::name_cmp(r.subject_name(), n.subject_name()) != 0,
                    None => true,
                });
                if mismatch {
                    Itav::new_root_ca_key_update(None, None, None)
                } else {
                    Itav::new_root_ca_key_update(
                        st.new_with_new.as_ref(),
                        st.new_with_old.as_ref(),
                        st.old_with_new.as_ref(),
                    )
                }
            }
            n if n == NID_id_it_crlStatusList => {
                let list = req.crl_status_list()?;
                let res = check_client_crl(&list, st.crl_out.as_ref());
                if res < 0 {
                    None
                } else {
                    Itav::new_crls(if res == 0 { None } else { st.crl_out.as_ref() })
                }
            }
            n if n == NID_id_it_certReqTemplate => {
                let reqtemp = CertTemplate::new()?;
                if let Some(r) = &st.ref_cert
                    && !reqtemp.fill_issuer(r.issuer_name())
                {
                    return None;
                }
                let eckeyalg = Atav::new_alg_id(NID_X9_62_id_ecPublicKey);
                let rsakeylen = Atav::new_rsa_key_len(4096);
                let mut keyspec: Option<Atavs> = None;
                let ok = Atavs::push1(&mut keyspec, eckeyalg.as_deref())
                    && Atavs::push1(&mut keyspec, rsakeylen.as_deref());
                if !ok {
                    return None;
                }
                Itav::new0_cert_req_template(reqtemp, keyspec)
            }
            _ => Itav::dup(req),
        }
    }
}

impl Server for Handler {
    /// `process_cert_request`.
    fn cert_request(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        _cert_req_id: i32,
        crm: Option<&CrmfMsgRef>,
        p10cr: Option<&ReqRef>,
    ) -> Option<CertResponse> {
        let func = c"process_cert_request";
        let Some(req) = req else {
            raise(CMP_R_NULL_ARGUMENT, 314, func);
            return None;
        };
        let mut st = self.0.borrow_mut();
        let bodytype = req.body_type();
        if st.send_error == 1 || st.send_error == bodytype {
            raise(CMP_R_ERROR_PROCESSING_MESSAGE, 319, func);
            return None;
        }

        if st.poll_count > 0 && st.curr_poll_count == 0 {
            // start polling
            st.req = Some(req.dup()?);
            let si = Pkisi::status_info(OSSL_CMP_PKISTATUS_waiting, 0, None)?;
            return Some(CertResponse {
                si,
                cert: None,
                chain: None,
                ca_pubs: None,
            });
        }
        if st.curr_poll_count >= st.poll_count {
            // give final response after polling
            st.curr_poll_count = 0;
        }

        // accept cert profile for cr messages only with the configured name
        if bodytype == OSSL_CMP_CR {
            for itav in req.geninfo_itavs() {
                if itav.type_nid() == NID_id_it_certProfile {
                    let strs = itav.cert_profile()?;
                    let Some(first) = strs.first() else {
                        raise(CMP_R_UNEXPECTED_CERTPROFILE, 354, func);
                        return None;
                    };
                    let Some(data) = first else {
                        raise(ERR_R_PASSED_INVALID_ARGUMENT, 360, func);
                        return None;
                    };
                    if data.as_slice() != b"profile1" {
                        raise(CMP_R_UNEXPECTED_CERTPROFILE, 365, func);
                        return None;
                    }
                    break;
                }
            }
        }

        // accept cert update request only for the reference cert, if given
        if bodytype == OSSL_CMP_KUR
            && let (Some(crm), Some(refcert)) = (crm, &st.ref_cert)
        {
            let Some((issuer, serial)) = cmp::old_cert_id(crm) else {
                raise(CMP_R_MISSING_CERTID, 379, func);
                return None;
            };
            if !refcert_cmp(Some(refcert), Some(issuer), serial) {
                raise(CMP_R_WRONG_CERTID, 385, func);
                return None;
            }
        }

        let cert = match &st.cert_out {
            Some(c) => Some(c.dup()?),
            None => None,
        };

        let central_keygen = cmp::centralkeygen_requested(crm, p10cr);
        if central_keygen < 0 {
            return None;
        }
        if central_keygen == 1 {
            let key = st.key_out.as_ref()?.dup()?;
            if !srv.cmp_ctx()?.set0_new_pkey(true, key) {
                return None;
            }
        }
        // Note that this uses newPkey to return the private key and does not check whether
        // the 'popo' field is absent.

        let chain = match &st.chain_out {
            Some(c) => Some(c.up_ref_copy()?),
            None => None,
        };
        let ca_pubs = match &st.ca_pubs_out {
            Some(c) => Some(c.up_ref_copy()?),
            None => None,
        };
        let si = st.status_out.as_ref()?.dup()?;
        Some(CertResponse {
            si,
            cert,
            chain,
            ca_pubs,
        })
    }

    /// `process_rr`.
    fn rr(
        &self,
        _srv: &SrvRef,
        req: Option<&MsgRef>,
        issuer: Option<NameRef<'_>>,
        serial: Option<&IntegerRef>,
    ) -> Option<Pkisi> {
        let func = c"process_rr";
        let Some(req) = req else {
            raise(CMP_R_NULL_ARGUMENT, 440, func);
            return None;
        };
        let st = self.0.borrow();
        if st.send_error == 1 || st.send_error == req.body_type() {
            raise(CMP_R_ERROR_PROCESSING_MESSAGE, 445, func);
            return None;
        }

        // allow any RR derived from CSR which does not include issuer and serial
        if (issuer.is_some() || serial.is_some())
            // accept revocation only for the reference cert, if given
            && !refcert_cmp(st.ref_cert.as_ref(), issuer, serial)
        {
            cmp::raise(
                CMP_R_REQUEST_NOT_ACCEPTED,
                c"apps/lib/cmp_mock_srv.c",
                453,
                func,
                Some("wrong certificate to revoke"),
            );
            return None;
        }
        st.status_out.as_ref()?.dup()
    }

    /// `process_genm`.
    fn genm(
        &self,
        _srv: &SrvRef,
        req: Option<&MsgRef>,
        items: Option<Vec<&ItavRef>>,
    ) -> Option<ItavStack> {
        let func = c"process_genm";
        let (Some(req), Some(items)) = (req, items) else {
            raise(CMP_R_NULL_ARGUMENT, 593, func);
            return None;
        };
        let send_error = self.0.borrow().send_error;
        if send_error == 1 || send_error == req.body_type() || items.len() > 1 {
            raise(CMP_R_ERROR_PROCESSING_MESSAGE, 599, func);
            return None;
        }
        let out = ItavStack::new()?;
        if let Some(item) = items.first() {
            let rsp = self.genm_itav(item.type_nid(), item)?;
            return out.push(rsp).then_some(out);
        }
        Some(out)
    }

    /// `process_error`.
    fn error(
        &self,
        _srv: &SrvRef,
        req: Option<&MsgRef>,
        si: Option<&PkisiRef>,
        error_code: Option<&IntegerRef>,
        details: Option<&FreeTextRef>,
    ) {
        if req.is_none() {
            raise(CMP_R_NULL_ARGUMENT, 632, c"process_error");
            return;
        }

        eprintf!("mock server received error:\n");

        match si {
            None => {
                eprintf!("pkiStatusInfo absent\n");
            }
            Some(si) => {
                let sibuf = si.snprint();
                eprintf!(
                    "pkiStatusInfo: {}\n",
                    sibuf.as_deref().unwrap_or("<invalid>")
                );
            }
        }

        match error_code {
            None => eprintf!("errorCode absent\n"),
            Some(c) => eprintf!("errorCode: {}\n", c.get()),
        };

        match details.filter(|d| !d.is_empty()) {
            None => {
                eprintf!("errorDetails absent\n");
            }
            Some(d) => {
                eprintf!("errorDetails: ");
                for i in 0..d.len() {
                    if i > 0 {
                        eprintf!(", ");
                    }
                    if let Some(b) = io::bio_err() {
                        d.print_ex(i, b, ASN1_STRFLGS_ESC_QUOTE as core::ffi::c_ulong);
                    }
                }
                eprintf!("\n");
            }
        }
    }

    /// `process_certConf`.
    fn cert_conf(
        &self,
        _srv: &SrvRef,
        req: Option<&MsgRef>,
        _cert_req_id: i32,
        cert_hash: Option<Vec<u8>>,
        _si: Option<&PkisiRef>,
    ) -> bool {
        let func = c"process_certConf";
        let (Some(req), Some(cert_hash)) = (req, cert_hash) else {
            raise(CMP_R_NULL_ARGUMENT, 676, func);
            return false;
        };
        let st = self.0.borrow();
        let cert_out = match &st.cert_out {
            Some(c) if st.send_error != 1 && st.send_error != req.body_type() => c,
            _ => {
                raise(CMP_R_ERROR_PROCESSING_MESSAGE, 682, func);
                return false;
            }
        };
        let Some(digest) = cert_out.digest_sig() else {
            return false;
        };
        if cert_hash != digest {
            raise(CMP_R_CERTHASH_UNMATCHED, 690, func);
            return false;
        }
        true
    }

    /// `process_pollReq`.
    fn poll_req(&self, _srv: &SrvRef, req: Option<&MsgRef>, _cert_req_id: i32) -> Option<Poll> {
        let func = c"process_pollReq";
        let Some(req) = req else {
            raise(CMP_R_NULL_ARGUMENT, 709, func);
            return None;
        };
        let mut st = self.0.borrow_mut();
        if st.send_error == 1 || st.send_error == req.body_type() {
            raise(CMP_R_ERROR_PROCESSING_MESSAGE, 715, func);
            return None;
        }
        if st.req.is_none() {
            // not currently in polling mode
            raise(CMP_R_UNEXPECTED_POLLREQ, 719, func);
            return None;
        }

        st.curr_poll_count += 1;
        if st.curr_poll_count >= st.poll_count {
            // end polling
            st.req.take().map(Poll::Done)
        } else {
            Some(Poll::After(i64::from(st.check_after_time)))
        }
    }

    /// `delayed_delivery`: whether to delay the response to a (non-polling) request.
    fn delayed_delivery(&self, _srv: &SrvRef, req: Option<&MsgRef>) -> i32 {
        let Some(req) = req else {
            raise(CMP_R_NULL_ARGUMENT, 241, c"delayed_delivery");
            return -1;
        };
        let req_type = req.body_type();

        // For ir/cr/p10cr/kur delayed delivery is handled separately in process_cert_request
        if [
            OSSL_CMP_IR,
            OSSL_CMP_CR,
            OSSL_CMP_P10CR,
            OSSL_CMP_KUR,
            OSSL_CMP_ERROR,
        ]
        .contains(&req_type)
        {
            // Client may use error to abort the ongoing polling
            return 0;
        }

        let mut st = self.0.borrow_mut();
        if st.poll_count > 0 && st.curr_poll_count == 0 {
            // start polling
            let Some(dup) = req.dup() else {
                return -1;
            };
            st.req = Some(dup);
            return 1;
        }
        0
    }

    /// `clean_transaction`: resets the state that belongs to a transaction.
    fn clean_transaction(&self, _srv: &SrvRef) -> bool {
        let mut st = self.0.borrow_mut();
        st.curr_poll_count = 0;
        st.req = None;
        true
    }
}
