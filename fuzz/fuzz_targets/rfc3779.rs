//! Fuzzes the RFC 3779 functions on untrusted values: the input is split in two, each half
//! decoded as IP address blocks and as AS identifiers, then checked for canonical form and
//! inheritance, its ranges read under every family, printed, put in canonical form, and
//! compared as subsets both ways (before and after). Nothing may crash or read out of bounds
//! (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    self as abi, ASIdentifiers, ASN1_ITEM, BIO, BIO_METHOD, IPAddrBlocks, IPAddressFamily,
    IPAddressOrRange, OPENSSL_STACK, X509V3_EXT_METHOD,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_item_d2i(v: *mut *mut c_void, p: *mut *const u8, len: c_long, it: *const ASN1_ITEM) -> *mut c_void;
    fn ASN1_item_free(v: *mut c_void, it: *const ASN1_ITEM);
    fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3_EXT_METHOD;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> c_int;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    fn X509v3_addr_is_canonical(addr: *mut IPAddrBlocks) -> c_int;
    fn X509v3_addr_canonize(addr: *mut IPAddrBlocks) -> c_int;
    fn X509v3_addr_inherits(addr: *mut IPAddrBlocks) -> c_int;
    fn X509v3_addr_subset(a: *mut IPAddrBlocks, b: *mut IPAddrBlocks) -> c_int;
    fn X509v3_addr_get_afi(f: *const IPAddressFamily) -> c_uint;
    fn X509v3_addr_get_range(aor: *mut IPAddressOrRange, afi: c_uint, min: *mut u8, max: *mut u8, length: c_int) -> c_int;
    fn X509v3_asid_is_canonical(asid: *mut ASIdentifiers) -> c_int;
    fn X509v3_asid_canonize(asid: *mut ASIdentifiers) -> c_int;
    fn X509v3_asid_inherits(asid: *mut ASIdentifiers) -> c_int;
    fn X509v3_asid_subset(a: *mut ASIdentifiers, b: *mut ASIdentifiers) -> c_int;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

/// The families' AFIs to read ranges under, known and not.
const AFIS: [c_uint; 3] = [abi::IANA_AFI_IPV4 as c_uint, abi::IANA_AFI_IPV6 as c_uint, 3];

/// Decodes `der` with the method of `nid`, or NULL.
unsafe fn decode(nid: c_int, der: &[u8]) -> (*mut c_void, *const ASN1_ITEM) {
    // SAFETY: a built-in method, which has an item.
    unsafe {
        let it = (*X509V3_EXT_get_nid(nid)).it.map_or(ptr::null(), |f| f());
        let mut p = der.as_ptr();
        let len = c_long::try_from(der.len()).unwrap_or(0);
        (ASN1_item_d2i(ptr::null_mut(), &mut p, len, it), it)
    }
}

/// Prints the value with its method.
unsafe fn print(nid: c_int, v: *mut c_void) {
    // SAFETY: a built-in method, which has an i2r; a BIO made and freed here.
    unsafe {
        let bio = BIO_new(BIO_s_mem());
        if let Some(i2r) = (*X509V3_EXT_get_nid(nid)).i2r {
            i2r(X509V3_EXT_get_nid(nid), v, bio, 2);
        }
        BIO_free(bio);
    }
}

/// Reads every range of every family.
unsafe fn ranges(addr: *mut IPAddrBlocks) {
    // SAFETY: decoded blocks, read within their counts.
    unsafe {
        for i in 0..OPENSSL_sk_num(addr.cast()) {
            let f = OPENSSL_sk_value(addr.cast(), i).cast::<IPAddressFamily>();
            X509v3_addr_get_afi(f);
            let c = (*f).ipAddressChoice;
            if c.is_null() || (*c).type_ != abi::IPAddressChoice_addressesOrRanges {
                continue;
            }
            let aors = (*c).u.addressesOrRanges;
            for j in 0..OPENSSL_sk_num(aors.cast()) {
                let aor = OPENSSL_sk_value(aors.cast(), j).cast::<IPAddressOrRange>();
                let (mut min, mut max) = ([0u8; 16], [0u8; 16]);
                for afi in AFIS {
                    for len in [4, 16] {
                        X509v3_addr_get_range(aor, afi, min.as_mut_ptr(), max.as_mut_ptr(), len);
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, rest)) = data.split_first() else { return };
    let (x, y) = rest.split_at(usize::from(cut).min(rest.len()));
    // SAFETY: values decoded here, used through their functions, and freed.
    unsafe {
        let addr = abi::NID_sbgp_ipAddrBlock;
        let (a, it) = decode(addr, x);
        let (b, _) = decode(addr, y);
        for v in [a, b] {
            if !v.is_null() {
                X509v3_addr_is_canonical(v.cast());
                X509v3_addr_inherits(v.cast());
                ranges(v.cast());
                print(addr, v);
            }
        }
        X509v3_addr_subset(a.cast(), b.cast());
        X509v3_addr_subset(b.cast(), a.cast());
        for v in [a, b] {
            if !v.is_null() && X509v3_addr_canonize(v.cast()) == 1 {
                print(addr, v);
            }
        }
        X509v3_addr_subset(a.cast(), b.cast());
        X509v3_addr_subset(b.cast(), a.cast());
        ASN1_item_free(a, it);
        ASN1_item_free(b, it);

        let asn = abi::NID_sbgp_autonomousSysNum;
        let (a, it) = decode(asn, x);
        let (b, _) = decode(asn, y);
        for v in [a, b] {
            if !v.is_null() {
                X509v3_asid_is_canonical(v.cast());
                X509v3_asid_inherits(v.cast());
                print(asn, v);
            }
        }
        X509v3_asid_subset(a.cast(), b.cast());
        for v in [a, b] {
            if !v.is_null() && X509v3_asid_canonize(v.cast()) == 1 {
                print(asn, v);
            }
        }
        X509v3_asid_subset(a.cast(), b.cast());
        X509v3_asid_subset(b.cast(), a.cast());
        ASN1_item_free(a, it);
        ASN1_item_free(b, it);
        ERR_clear_error();
    }
});
