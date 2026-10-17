//! Fuzzes the attribute certificate extensions on untrusted values: the input's first octet
//! picks an extension (time specification, targeting information, the authority attribute
//! identifier, basic attribute constraints, issued on behalf of, role specification
//! certificate identifiers, subject directory attributes, user notices, attribute
//! descriptors, attribute mappings, allowed attribute assignments, the AA issuing distribution
//! point), the rest is decoded with its method, encoded again, and printed (`i2r`, or `i2v`)
//! at two indents. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{self as abi, ASN1_ITEM, BIO, BIO_METHOD, X509V3_EXT_METHOD, stack_st_CONF_VALUE};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_item_d2i(v: *mut *mut c_void, p: *mut *const u8, len: c_long, it: *const ASN1_ITEM) -> *mut c_void;
    fn ASN1_item_i2d(v: *const c_void, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int;
    fn ASN1_item_free(v: *mut c_void, it: *const ASN1_ITEM);
    fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3_EXT_METHOD;
    fn X509V3_conf_free(v: *mut c_void);
    fn OPENSSL_sk_pop_free(sk: *mut c_void, f: Option<unsafe extern "C" fn(*mut c_void)>);
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

const NIDS: [c_int; 13] = [
    abi::NID_time_specification,
    abi::NID_target_information,
    abi::NID_authority_attribute_identifier,
    abi::NID_basic_att_constraints,
    abi::NID_issued_on_behalf_of,
    abi::NID_role_spec_cert_identifier,
    abi::NID_subject_directory_attributes,
    abi::NID_user_notice,
    abi::NID_attribute_descriptor,
    abi::NID_attribute_mappings,
    abi::NID_allowed_attribute_assignments,
    abi::NID_id_aa_issuing_distribution_point,
    abi::NID_single_use,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, der)) = data.split_first() else { return };
    let nid = NIDS[usize::from(pick) % NIDS.len()];
    // SAFETY: a built-in method, which has an item; the input's octets; values decoded,
    // encoded, printed, and freed here.
    unsafe {
        let m = X509V3_EXT_get_nid(nid);
        let it = (*m).it.map_or(ptr::null(), |f| f());
        let mut p = der.as_ptr();
        let len = c_long::try_from(der.len()).unwrap_or(0);
        let v = ASN1_item_d2i(ptr::null_mut(), &mut p, len, it);
        if !v.is_null() {
            let mut out = ptr::null_mut();
            if ASN1_item_i2d(v, &mut out, it) > 0 {
                CRYPTO_free(out.cast(), ptr::null(), 0);
            }
            let bio = BIO_new(BIO_s_mem());
            for indent in [0, 4] {
                if let Some(i2r) = (*m).i2r {
                    i2r(m, v, bio, indent);
                }
                if let Some(i2v) = (*m).i2v {
                    let list: *mut stack_st_CONF_VALUE = i2v(m, v, ptr::null_mut());
                    OPENSSL_sk_pop_free(list.cast(), Some(X509V3_conf_free));
                }
            }
            BIO_free(bio);
            ASN1_item_free(v, it);
        }
        ERR_clear_error();
    }
});
