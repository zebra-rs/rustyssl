//! Printing certificates' parts (`t_x509.c`): signatures, in hex or by their key type's
//! printer, and serial numbers. The rest of `t_x509.c` is in `tprint.rs`.

use core::ffi::{CStr, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_STRING, BIGNUM, BIO, ERR_LIB_X509, NID_dsa, NID_rsaEncryption,
    NID_rsassaPss, NID_undef, V_ASN1_NEG_INTEGER, X509_ALGOR,
};

use crate::asn1::integer::ASN1_INTEGER_get_int64;
use crate::bio::BIO_indent;
use crate::bn::conv::ASN1_bn_print;
use crate::dsa_ops::{DSA_SIG_free, DSA_SIG_get0, d2i_DSA_SIG};
use crate::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::evp::pkey::ameth::{EVP_PKEY_asn1_find, EVP_PKEY_asn1_get0_info};
use crate::evp::pkey::rsa::{pss_decode, pss_param_print};
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2nid;
use crate::objects::sigid::OBJ_find_sigid_algs;
use crate::rsa_asn1::RSA_PSS_PARAMS_free;
use crate::x509v3::text::Out;

/// A string's octets.
///
/// # Safety
/// `s` is a live string.
unsafe fn octets<'a>(s: &ASN1_STRING) -> &'a [u8] {
    match usize::try_from(s.length) {
        // SAFETY: a string's data holds its length.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

ffi_export! {
    /// Prints the signature in hex, 18 octets (`xx:`) to a line, each line `indent` in, then a
    /// newline: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `sig` is NULL or a live string.
    pub unsafe extern "C" fn X509_signature_dump(bp: *mut BIO, sig: *const ASN1_STRING, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(sig) = (unsafe { sig.as_ref() }) else { return 0 };
        // SAFETY: as above.
        let out = unsafe { Out::new(bp) };
        // SAFETY: the caller's string.
        let s = unsafe { octets(sig) };
        for (i, &c) in s.iter().enumerate() {
            if i % 18 == 0 {
                if i > 0 && out.print("\n") <= 0 {
                    return 0;
                }
                // SAFETY: the caller's BIO.
                if unsafe { BIO_indent(bp, indent, indent) } <= 0 {
                    return 0;
                }
            }
            let sep = if i + 1 == s.len() { "" } else { ":" };
            if out.print(&format!("{c:02x}{sep}")) <= 0 {
                return 0;
            }
        }
        c_int::from(out.print("\n") == 1)
    }
}

/// `rsa_sig_print`: an RSA-PSS signature's parameters (a newline for others), then the
/// signature in hex.
///
/// # Safety
/// `bp` is a live BIO; `alg` is a live AlgorithmIdentifier; `sig` is NULL or a live string.
unsafe fn rsa_sig_print(
    bp: *mut BIO,
    alg: &X509_ALGOR,
    sig: *const ASN1_STRING,
    indent: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let out = unsafe { Out::new(bp) };
    // SAFETY: its algorithm.
    if unsafe { OBJ_obj2nid(alg.algorithm) } == NID_rsassaPss {
        // SAFETY: the caller's AlgorithmIdentifier.
        let pss = unsafe { pss_decode(alg) };
        // SAFETY: the caller's BIO; the parameters, or NULL.
        let ok = unsafe { pss_param_print(bp, false, pss, indent) };
        // SAFETY: decoded above, or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        if !ok {
            return 0;
        }
    } else if out.print("\n") <= 0 {
        return 0;
    }
    if sig.is_null() {
        return 1;
    }
    // SAFETY: the caller's guarantee.
    unsafe { X509_signature_dump(bp, sig, indent) }
}

/// `dsa_sig_print`: a DSA signature's `r` and `s`, or the signature in hex if it doesn't
/// decode.
///
/// # Safety
/// `bp` is a live BIO; `sig` is NULL or a live string.
unsafe fn dsa_sig_print(bp: *mut BIO, sig: *const ASN1_STRING, indent: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let out = unsafe { Out::new(bp) };
    // SAFETY: as above.
    let Some(s) = (unsafe { sig.as_ref() }) else {
        return c_int::from(out.print("\n") > 0);
    };
    let mut p = s.data.cast_const();
    // SAFETY: a local; the string's octets.
    let dsa_sig = unsafe { d2i_DSA_SIG(ptr::null_mut(), &raw mut p, s.length.into()) };
    if dsa_sig.is_null() {
        if out.print("\n") <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        return unsafe { X509_signature_dump(bp, sig, indent) };
    }
    let (mut r, mut sv): (*const BIGNUM, *const BIGNUM) = (ptr::null(), ptr::null());
    // SAFETY: decoded above; locals.
    unsafe { DSA_SIG_get0(dsa_sig, &raw mut r, &raw mut sv) };
    let print = |label: &CStr, n: *const BIGNUM| {
        // SAFETY: the caller's BIO; a static label; the signature's number.
        (unsafe { ASN1_bn_print(bp, label.as_ptr(), n, ptr::null_mut(), indent) }) != 0
    };
    let ok = out.write(b"\n") == 1 && print(c"r:   ", r) && print(c"s:   ", sv);
    // SAFETY: decoded above.
    unsafe { DSA_SIG_free(dsa_sig) };
    c_int::from(ok)
}

/// The signature printer of the algorithm's key type (an `EVP_PKEY_ASN1_METHOD`'s
/// `sig_print`: RSA's, RSA-PSS's, and DSA's), and its result; `None` for none.
///
/// # Safety
/// `bp` is a live BIO; `alg` is a live AlgorithmIdentifier; `sig` is NULL or a live string.
pub(crate) unsafe fn sig_print(
    bp: *mut BIO,
    alg: &X509_ALGOR,
    sig: *const ASN1_STRING,
    indent: c_int,
) -> Option<c_int> {
    // SAFETY: its algorithm.
    let sig_nid = unsafe { OBJ_obj2nid(alg.algorithm) };
    if sig_nid == NID_undef {
        return None;
    }
    let (mut dig_nid, mut pkey_nid) = (0, 0);
    // SAFETY: locals.
    if unsafe { OBJ_find_sigid_algs(sig_nid, &raw mut dig_nid, &raw mut pkey_nid) } == 0 {
        return None;
    }
    // SAFETY: no engine.
    let ameth = unsafe { EVP_PKEY_asn1_find(ptr::null_mut(), pkey_nid) };
    if ameth.is_null() {
        return None;
    }
    let mut id = NID_undef;
    let none = ptr::null_mut();
    // SAFETY: a local and no other outputs; the method found above.
    unsafe { EVP_PKEY_asn1_get0_info(&raw mut id, none, none, none.cast(), none.cast(), ameth) };
    match id {
        n if n == NID_rsaEncryption || n == NID_rsassaPss => {
            // SAFETY: the caller's guarantee.
            Some(unsafe { rsa_sig_print(bp, alg, sig, indent) })
        }
        // SAFETY: as above.
        n if n == NID_dsa => Some(unsafe { dsa_sig_print(bp, sig, indent) }),
        _ => None,
    }
}

/// `ossl_serial_number_print`: ` n (0xh)` for one that fits in 64 bits, otherwise its octets
/// in hex on the next line, `indent` in (` (Empty)` for none): 0, or -1 if it can't print.
///
/// # Safety
/// `out` is a live BIO; `bs` is a live INTEGER.
pub(crate) unsafe fn serial_number_print(out: *mut BIO, bs: &ASN1_INTEGER, indent: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let o = unsafe { Out::new(out) };
    // SAFETY: as above.
    let data = unsafe { octets(bs) };
    if bs.length == 0 {
        return if o.print(" (Empty)") <= 0 { -1 } else { 0 };
    }
    let mut l: i64 = 0;
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: a local; the caller's INTEGER.
    let ok = unsafe { ASN1_INTEGER_get_int64(&raw mut l, bs) } != 0;
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    let neg = bs.type_ == V_ASN1_NEG_INTEGER;
    let text = if ok {
        let (sign, ul) = if neg {
            ("-", 0u64.wrapping_sub(l.cast_unsigned()))
        } else {
            ("", l.cast_unsigned())
        };
        format!(" {sign}{ul} ({sign}0x{ul:x})")
    } else {
        let pad = usize::try_from(indent.unsigned_abs()).unwrap_or(0);
        let hex: Vec<String> = data.iter().map(|c| format!("{c:02x}")).collect();
        format!(
            "\n{:pad$}{}{}",
            "",
            if neg { " (Negative)" } else { "" },
            hex.join(":")
        )
    };
    if o.print(&text) <= 0 { -1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_signature_is_refused() {
        // SAFETY: a NULL signature, which is refused before the BIO is used.
        let r = unsafe { X509_signature_dump(ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(r, 0);
    }
}
