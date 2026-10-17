//! The default and base providers' text encoders (`encode_key2text.c`, and the helpers it uses
//! from `encoder_lib.c` and the post-quantum codecs): what `EVP_PKEY_print_public`,
//! `_private`, and `_params` print of a provided key, and the `TEXT` output of the encoders.
//!
//! As OpenSSL's, the text is written as it's made, so a key missing a part it's asked for is
//! printed up to that part; the numbers are `ossl_bio_print_labeled_bignum`'s (a word's
//! decimal and hex, or colon-separated octets fifteen to a line), and octet strings
//! `ossl_bio_print_labeled_buf`'s.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BIO, EC_GROUP, ERR_LIB_OSSL_ENCODER, ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
    NID_X9_62_characteristic_two_field, NID_mgf1, NID_sha1, NID_sm2, NID_undef,
    OPENSSL_EC_NAMED_CURVE, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, PROV_R_INVALID_KEY, PROV_R_MISSING_KEY,
    PROV_R_NOT_A_PRIVATE_KEY, PROV_R_NOT_A_PUBLIC_KEY,
};
use rustyssl_crypto::bn::BigNum;

use crate::bio::BIO_write;
use crate::err;
use crate::mem;

/// `LABELED_BUF_PRINT_WIDTH`: the octets on a line.
const WIDTH: usize = 15;

/// A key-to-text function (`type##_to_text`).
pub(super) type ToText = unsafe fn(*mut BIO, *const c_void, c_int) -> c_int;

/// What the text goes to, a write at a time (`BIO_printf`'s).
#[derive(Clone, Copy)]
struct Out(*mut BIO);

impl Out {
    /// Writes the text; false if it can't (`BIO_printf(...) <= 0`).
    fn put(self, s: &str) -> bool {
        let Ok(n) = c_int::try_from(s.len()) else {
            return false;
        };
        // SAFETY: a live BIO (the encoder's, over the caller's core BIO); the text's octets.
        n > 0 && unsafe { BIO_write(self.0, s.as_ptr().cast(), n) } > 0
    }
}

/// A C string as `BIO_printf`'s `%s` prints it: `<NULL>` for none.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text(s: *const core::ffi::c_char) -> String {
    if s.is_null() {
        return "<NULL>".to_owned();
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned()
}

/// A NID's short name as `%s` prints it (`<NULL>` for none).
fn sn(nid: c_int) -> String {
    // SAFETY: a number.
    let name = unsafe { crate::objects::OBJ_nid2sn(nid) };
    // SAFETY: NULL or a static name.
    unsafe { text(name) }
}

/// `ossl_bio_print_labeled_bignum`: the label, then a word's value in decimal and hex, or the
/// octets in hex (with a leading 00 when the top bit is set) fifteen to a line, indented by
/// four; false for no number.
fn labeled_bignum(out: Out, label: Option<&str>, bn: Option<&BigNum>) -> bool {
    let Some(bn) = bn else { return false };
    let (label, post) = match label {
        Some(l) => (l, " "),
        None => ("", ""),
    };
    if bn.is_zero() {
        return out.put(&format!("{label}{post}0\n"));
    }
    if bn.num_bytes() <= 8 {
        let neg = if bn.is_negative() { "-" } else { "" };
        let w = bn.get_word();
        return out.put(&format!("{label}{post}{neg}{w} ({neg}0x{w:x})\n"));
    }
    let hex = bn.to_hex();
    let (digits, neg) = match hex.strip_prefix('-') {
        Some(d) => (d, " (Negative)"),
        None => (hex.as_str(), ""),
    };
    if !out.put(&format!("{label}{neg}\n")) || !out.put("    ") {
        return false;
    }
    let mut bytes = 0usize;
    let mut use_sep = false;
    if digits.as_bytes().first().is_some_and(|&c| c >= b'8') {
        if !out.put("00") {
            return false;
        }
        bytes = 1;
        use_sep = true;
    }
    for pair in digits.as_bytes().chunks(2) {
        if bytes.is_multiple_of(15) && bytes > 0 {
            if !out.put(":\n    ") {
                return false;
            }
            use_sep = false;
        }
        let pair = String::from_utf8_lossy(pair).to_ascii_lowercase();
        if !out.put(&format!("{}{pair}", if use_sep { ":" } else { "" })) {
            return false;
        }
        bytes = bytes.saturating_add(1);
        use_sep = true;
    }
    out.put("\n")
}

/// `ossl_bio_print_labeled_bignum` of a `BIGNUM` (false for NULL).
///
/// # Safety
/// `bn` is NULL or a live `BIGNUM`.
unsafe fn labeled_c_bignum(out: Out, label: &str, bn: *const BIGNUM) -> bool {
    // SAFETY: the caller's guarantee.
    let v = unsafe { crate::bn::value(bn) };
    labeled_bignum(out, Some(label), v.as_ref())
}

/// `ossl_bio_print_labeled_buf`: the label, then the octets in hex fifteen to a line, indented
/// by four.
fn labeled_buf(out: Out, label: &str, buf: &[u8]) -> bool {
    if !out.put(&format!("{label}\n")) {
        return false;
    }
    for (i, b) in buf.iter().enumerate() {
        if i.is_multiple_of(WIDTH) {
            if i > 0 && !out.put("\n") {
                return false;
            }
            if !out.put("    ") {
                return false;
            }
        }
        let sep = if i.saturating_add(1) == buf.len() {
            ""
        } else {
            ":"
        };
        if !out.put(&format!("{b:02x}{sep}")) {
            return false;
        }
    }
    out.put("\n")
}

/// `ossl_bio_print_ffc_params`: a named group's name, or the numbers, the seed, and the
/// generation's counters.
fn ffc_params(out: Out, ffc: &crate::ffc::Params) -> bool {
    if ffc.nid != NID_undef {
        let Some(group) = rustyssl_crypto::ffc::by_uid(ffc.nid) else {
            return false;
        };
        return out.put(&format!("GROUP: {}\n", group.name));
    }
    labeled_bignum(out, Some("P:   "), ffc.p.as_ref())
        && (ffc.q.is_none() || labeled_bignum(out, Some("Q:   "), ffc.q.as_ref()))
        && labeled_bignum(out, Some("G:   "), ffc.g.as_ref())
        && (ffc.j.is_none() || labeled_bignum(out, Some("J:   "), ffc.j.as_ref()))
        && ffc
            .seed
            .as_deref()
            .is_none_or(|s| labeled_buf(out, "SEED:", s))
        && (ffc.gindex == -1 || out.put(&format!("gindex: {}\n", ffc.gindex)))
        && (ffc.pcounter == -1 || out.put(&format!("pcounter: {}\n", ffc.pcounter)))
        && (ffc.h == 0 || out.put(&format!("h: {}\n", ffc.h)))
}

/// The label a selection asks for: the private key's, the public key's, or the parameters'.
fn label_of(
    selection: c_int,
    private: &'static str,
    public: &'static str,
    params: Option<&'static str>,
) -> Option<&'static str> {
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        Some(private)
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        Some(public)
    } else if selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS != 0 {
        params
    } else {
        None
    }
}

/// `dh_to_text` and `dsa_to_text`: the kind and the prime's bits, the keys asked for, the
/// parameters, and (DH's) the recommended private key length.
///
/// # Safety
/// `out` is a live BIO.
#[allow(clippy::too_many_arguments, reason = "the two functions' labels")]
unsafe fn ffc_to_text(
    out: *mut BIO,
    f: &str,
    state: Option<(crate::ffc::Params, Option<BigNum>, Option<BigNum>, i32)>,
    selection: c_int,
    labels: (&'static str, &'static str, &'static str),
    key_labels: (&str, &str),
    length: bool,
) -> c_int {
    let o = Out(out);
    let Some((params, pub_key, priv_key, len)) = state else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, f);
        return 0;
    };
    let type_label = label_of(selection, labels.0, labels.1, Some(labels.2));
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 && priv_key.is_none() {
        err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY, f);
        return 0;
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR != 0 && pub_key.is_none() {
        err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, f);
        return 0;
    }
    let Some(p) = params.p.as_ref() else {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, f);
        return 0;
    };
    let ok = o.put(&format!(
        "{}: ({} bit)\n",
        type_label.unwrap_or("<NULL>"),
        p.num_bits()
    )) && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0
        || labeled_bignum(o, Some(key_labels.0), priv_key.as_ref()))
        && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0
            || labeled_bignum(o, Some(key_labels.1), pub_key.as_ref()))
        && (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS == 0 || ffc_params(o, &params))
        && (!length || len <= 0 || o.put(&format!("recommended-private-length: {len} bits\n")));
    c_int::from(ok)
}

/// `dh_to_text`.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or a DH key.
pub(super) unsafe fn dh_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let state = unsafe { crate::dh::dh(key.cast()) }.map(|d| {
        let s = d.lock();
        (
            s.params.clone(),
            s.pub_key.clone(),
            s.priv_key.clone(),
            s.length,
        )
    });
    // SAFETY: the caller's BIO.
    unsafe {
        ffc_to_text(
            out,
            "dh_to_text",
            state,
            selection,
            ("DH Private-Key", "DH Public-Key", "DH Parameters"),
            ("private-key:", "public-key:"),
            true,
        )
    }
}

/// `dsa_to_text`.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or a DSA key.
pub(super) unsafe fn dsa_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let state = unsafe { crate::dsa::dsa(key.cast()) }.map(|d| {
        let s = d.lock();
        (s.params.clone(), s.pub_key.clone(), s.priv_key.clone(), 0)
    });
    // SAFETY: the caller's BIO.
    unsafe {
        ffc_to_text(
            out,
            "dsa_to_text",
            state,
            selection,
            ("Private-Key", "Public-Key", "DSA-Parameters"),
            ("priv:", "pub: "),
            false,
        )
    }
}

/// `ec_param_explicit_to_text`: the field type, the curve (`Prime:` or, for a binary field,
/// the basis type and `Polynomial:`), A, B, the generator, the order, the cofactor, and the
/// seed.
///
/// # Safety
/// `group` is a live group.
unsafe fn ec_explicit(o: Out, group: *const EC_GROUP) -> bool {
    use crate::bn::{BN_free, BN_new};
    use crate::ec::group::{
        EC_GROUP_get_basis_type, EC_GROUP_get_curve, EC_GROUP_get_field_type,
        EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len, EC_GROUP_get0_cofactor,
        EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed,
    };
    // SAFETY: the caller's group.
    let field = unsafe { EC_GROUP_get_field_type(group) };
    // SAFETY: as above.
    let order = unsafe { EC_GROUP_get0_order(group) };
    if order.is_null() {
        return false;
    }
    // SAFETY: as above.
    let seed = unsafe { EC_GROUP_get0_seed(group) };
    let seed_len = if seed.is_null() {
        0
    } else {
        // SAFETY: as above.
        unsafe { EC_GROUP_get_seed_len(group) }
    };
    // SAFETY: as above.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
    if !o.put(&format!("Field Type: {}\n", sn(field))) {
        return false;
    }
    // ec_param_explicit_curve_to_text
    // SAFETY: no preconditions.
    let p = unsafe { BN_new() };
    // SAFETY: as above.
    let a = unsafe { BN_new() };
    // SAFETY: as above.
    let b = unsafe { BN_new() };
    let free = || {
        // SAFETY: made above (or NULL).
        unsafe { BN_free(p) };
        // SAFETY: as above.
        unsafe { BN_free(a) };
        // SAFETY: as above.
        unsafe { BN_free(b) };
    };
    let made = !b.is_null() && !a.is_null() && !p.is_null();
    // SAFETY: the group; the new numbers.
    if !made || unsafe { EC_GROUP_get_curve(group, p, a, b, ptr::null_mut()) } == 0 {
        free();
        return false;
    }
    let mut plabel = "Prime:";
    if field == NID_X9_62_characteristic_two_field {
        // SAFETY: the group.
        let basis = unsafe { EC_GROUP_get_basis_type(group) };
        if basis == NID_undef || !o.put(&format!("Basis Type: {}\n", sn(basis))) {
            free();
            return false;
        }
        plabel = "Polynomial:";
    }
    // SAFETY: the numbers made above.
    let curve = unsafe { labeled_c_bignum(o, plabel, p) }
        // SAFETY: as above.
        && unsafe { labeled_c_bignum(o, "A:   ", a) }
        // SAFETY: as above.
        && unsafe { labeled_c_bignum(o, "B:   ", b) };
    free();
    if !curve {
        return false;
    }
    // ec_param_explicit_gen_to_text
    // SAFETY: the group.
    let form = unsafe { EC_GROUP_get_point_conversion_form(group) };
    // SAFETY: as above.
    let point = unsafe { EC_GROUP_get0_generator(group) };
    if point.is_null() {
        return false;
    }
    let glabel = match form {
        rustyssl_abi::POINT_CONVERSION_COMPRESSED => "Generator (compressed):",
        rustyssl_abi::POINT_CONVERSION_UNCOMPRESSED => "Generator (uncompressed):",
        rustyssl_abi::POINT_CONVERSION_HYBRID => "Generator (hybrid):",
        _ => return false,
    };
    let mut buf: *mut c_uchar = ptr::null_mut();
    // SAFETY: the group and its generator; a new buffer into `buf`.
    let buflen = unsafe {
        crate::ec::point::EC_POINT_point2buf(group, point, form, &raw mut buf, ptr::null_mut())
    };
    if buflen == 0 {
        return false;
    }
    // SAFETY: the new buffer's `buflen` octets.
    let gen_ok = labeled_buf(o, glabel, unsafe {
        core::slice::from_raw_parts(buf, buflen)
    });
    // SAFETY: made above.
    unsafe { mem::release_clean(buf.cast(), buflen) };
    if !gen_ok {
        return false;
    }
    // SAFETY: the group's numbers.
    (unsafe { labeled_c_bignum(o, "Order: ", order) })
        // SAFETY: as above.
        && (cofactor.is_null() || unsafe { labeled_c_bignum(o, "Cofactor: ", cofactor) })
        // SAFETY: the group's seed of `seed_len` octets.
        && (seed.is_null() || labeled_buf(o, "Seed:", unsafe { core::slice::from_raw_parts(seed, seed_len) }))
}

/// `ec_param_to_text`: a named curve's OID and NIST name, or the explicit parameters.
///
/// # Safety
/// `group` is a live group.
unsafe fn ec_params(o: Out, group: *const EC_GROUP) -> bool {
    use crate::ec::group::{EC_GROUP_get_asn1_flag, EC_GROUP_get_curve_name};
    // SAFETY: the caller's group.
    if unsafe { EC_GROUP_get_asn1_flag(group) } & OPENSSL_EC_NAMED_CURVE == 0 {
        // SAFETY: as above.
        return unsafe { ec_explicit(o, group) };
    }
    // SAFETY: as above.
    let nid = unsafe { EC_GROUP_get_curve_name(group) };
    if nid == NID_undef {
        return false;
    }
    if !o.put(&format!("ASN1 OID: {}\n", sn(nid))) {
        return false;
    }
    // SAFETY: a number.
    let nist = unsafe { crate::ec::curves::EC_curve_nid2nist(nid) };
    // SAFETY: NULL or a static name.
    nist.is_null() || o.put(&format!("NIST CURVE: {}\n", unsafe { text(nist) }))
}

/// `ec_to_text`: the kind and the order's bits, the private and public keys asked for, and the
/// parameters (the result, which fails without them).
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an EC key.
pub(super) unsafe fn ec_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    use crate::ec::group::{EC_GROUP_get_curve_name, EC_GROUP_order_bits};
    use crate::ec::key::{
        EC_KEY_get_conv_form, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
        EC_KEY_key2buf, EC_KEY_priv2buf,
    };
    const F: &str = "ec_to_text";
    let o = Out(out);
    let ec: *const rustyssl_abi::EC_KEY = key.cast();
    if ec.is_null() {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
        return 0;
    }
    // SAFETY: the key's group.
    let curve = unsafe { EC_GROUP_get_curve_name(group) };
    let type_label = if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        Some("Private-Key")
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        Some("Public-Key")
    } else if selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS != 0 && curve != NID_sm2 {
        Some("EC-Parameters")
    } else {
        None
    };
    let mut priv_buf: *mut c_uchar = ptr::null_mut();
    let mut priv_len = 0usize;
    let mut pub_buf: *mut c_uchar = ptr::null_mut();
    let mut pub_len = 0usize;
    let release = |priv_buf: *mut c_uchar, priv_len: usize, pub_buf: *mut c_uchar| {
        // SAFETY: made here, or NULL.
        unsafe { mem::release_clean(priv_buf.cast(), priv_len) };
        // SAFETY: as above.
        unsafe { mem::release(pub_buf.cast()) };
    };
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        // SAFETY: the caller's key.
        if unsafe { EC_KEY_get0_private_key(ec) }.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY, F);
            return 0;
        }
        // SAFETY: as above; a new buffer into `priv_buf`.
        priv_len = unsafe { EC_KEY_priv2buf(ec, &raw mut priv_buf) };
        if priv_len == 0 {
            release(priv_buf, priv_len, pub_buf);
            return 0;
        }
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR != 0 {
        // SAFETY: the caller's key.
        if unsafe { EC_KEY_get0_public_key(ec) }.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, F);
            release(priv_buf, priv_len, pub_buf);
            return 0;
        }
        // SAFETY: as above.
        let form = unsafe { EC_KEY_get_conv_form(ec) };
        // SAFETY: as above; a new buffer into `pub_buf`.
        pub_len = unsafe { EC_KEY_key2buf(ec, form, &raw mut pub_buf, ptr::null_mut()) };
        if pub_len == 0 {
            release(priv_buf, priv_len, pub_buf);
            return 0;
        }
    }
    // SAFETY: the key's group.
    let bits = unsafe { EC_GROUP_order_bits(group) };
    // SAFETY: the buffer made above, of its length.
    let privs =
        (!priv_buf.is_null()).then(|| unsafe { core::slice::from_raw_parts(priv_buf, priv_len) });
    // SAFETY: as above.
    let pubs =
        (!pub_buf.is_null()).then(|| unsafe { core::slice::from_raw_parts(pub_buf, pub_len) });
    let mut ret = 0;
    if type_label.is_none_or(|l| o.put(&format!("{l}: ({bits} bit)\n")))
        && privs.is_none_or(|p| labeled_buf(o, "priv:", p))
        && pubs.is_none_or(|p| labeled_buf(o, "pub:", p))
        && selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS != 0
    {
        // SAFETY: the key's group.
        ret = c_int::from(unsafe { ec_params(o, group) });
    }
    release(priv_buf, priv_len, pub_buf);
    ret
}

/// `ecx_to_text`: the private key (or the kind of public key), then the public key.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an ECX key.
pub(super) unsafe fn ecx_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    const F: &str = "ecx_to_text";
    let o = Out(out);
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { crate::ecx::key(key) }) else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let name = match k.kind {
        crate::ecx::EcxType::X25519 => "X25519",
        crate::ecx::EcxType::X448 => "X448",
        crate::ecx::EcxType::Ed25519 => "ED25519",
        crate::ecx::EcxType::Ed448 => "ED448",
    };
    let keylen = k.keylen();
    let (privkey, pubkey, haspubkey) = {
        let s = k.lock();
        (
            s.privkey.clone().map(rustyssl_crypto::bn::Zeroizing::new),
            s.pubkey.get(..keylen).unwrap_or_default().to_vec(),
            s.haspubkey,
        )
    };
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        let Some(privkey) = privkey else {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY, F);
            return 0;
        };
        if !o.put(&format!("{name} Private-Key:\n"))
            || !labeled_buf(o, "priv:", privkey.get(..keylen).unwrap_or_default())
        {
            return 0;
        }
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        if !haspubkey {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, F);
            return 0;
        }
        if !o.put(&format!("{name} Public-Key:\n")) {
            return 0;
        }
    }
    c_int::from(labeled_buf(o, "pub:", &pubkey))
}

/// `rsa_to_text`: the kind, the bits (and primes), the numbers asked for, and an RSA-PSS key's
/// restrictions.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an RSA key.
pub(super) unsafe fn rsa_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    let o = Out(out);
    // SAFETY: the caller's guarantee.
    let Some(r) = (unsafe { crate::rsa::rsa(key.cast()) }) else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "rsa_to_text");
        return 0;
    };
    let state = r.lock().clone();
    let k = &state.key;
    let private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0;
    let (type_label, modulus_label, exponent_label) = if private {
        ("Private-Key", Some("modulus:"), Some("publicExponent:"))
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        ("Public-Key", Some("Modulus:"), Some("Exponent:"))
    } else {
        ("RSA key", None, None)
    };
    // ossl_rsa_get0_all_params: none without p.
    let mut factors: Vec<Option<&BigNum>> = Vec::new();
    let mut exps: Vec<Option<&BigNum>> = Vec::new();
    let mut coeffs: Vec<Option<&BigNum>> = Vec::new();
    if k.p.is_some() {
        factors = vec![k.p.as_ref(), k.q.as_ref()];
        exps = vec![k.dmp1.as_ref(), k.dmq1.as_ref()];
        coeffs = vec![k.iqmp.as_ref()];
        for x in &k.extra {
            factors.push(Some(&x.r));
            exps.push(Some(&x.d));
            coeffs.push(Some(&x.t));
        }
    }
    let bits = k.n.as_ref().map_or(0, BigNum::num_bits);
    let header = if private {
        format!("{type_label}: ({bits} bit, {} primes)\n", factors.len())
    } else {
        format!("{type_label}: ({bits} bit)\n")
    };
    fn at<'a>(v: &[Option<&'a BigNum>], i: usize) -> Option<&'a BigNum> {
        v.get(i).copied().flatten()
    }
    if !o.put(&header)
        || !labeled_bignum(o, modulus_label, k.n.as_ref())
        || !labeled_bignum(o, exponent_label, k.e.as_ref())
    {
        return 0;
    }
    if private {
        let ok = labeled_bignum(o, Some("privateExponent:"), k.d.as_ref())
            && labeled_bignum(o, Some("prime1:"), at(&factors, 0))
            && labeled_bignum(o, Some("prime2:"), at(&factors, 1))
            && labeled_bignum(o, Some("exponent1:"), at(&exps, 0))
            && labeled_bignum(o, Some("exponent2:"), at(&exps, 1))
            && labeled_bignum(o, Some("coefficient:"), at(&coeffs, 0));
        if !ok {
            return 0;
        }
        for i in 2..factors.len() {
            let n = i.saturating_add(1);
            let ok = o.put(&format!("prime{n}:"))
                && labeled_bignum(o, None, at(&factors, i))
                && o.put(&format!("exponent{n}:"))
                && labeled_bignum(o, None, at(&exps, i))
                && o.put(&format!("coefficient{n}:"))
                && labeled_bignum(o, None, at(&coeffs, i.saturating_sub(1)));
            if !ok {
                return 0;
            }
        }
    }
    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS != 0 {
        let pss = state.pss;
        let ok = match state.kind {
            crate::rsa::Kind::Rsa => !pss.restricted() || o.put("(INVALID PSS PARAMETERS)\n"),
            crate::rsa::Kind::RsaPss if !pss.restricted() => {
                o.put("No PSS parameter restrictions\n")
            }
            crate::rsa::Kind::RsaPss => {
                let name = |nid: c_int| {
                    super::rsa_kmgmt::oaeppss_nid2name(nid)
                        .map_or_else(|| "<NULL>".to_owned(), |n| n.to_string_lossy().into_owned())
                };
                let mgf = if pss.mask_gen == NID_mgf1 {
                    "MGF1"
                } else {
                    "<NULL>"
                };
                o.put("PSS parameter restrictions:\n")
                    && o.put(&format!(
                        "  Hash Algorithm: {}{}\n",
                        name(pss.hash),
                        if pss.hash == NID_sha1 {
                            " (default)"
                        } else {
                            ""
                        }
                    ))
                    && o.put(&format!(
                        "  Mask Algorithm: {mgf} with {}{}\n",
                        name(pss.mask_gen_hash),
                        if pss.mask_gen == NID_mgf1 && pss.mask_gen_hash == NID_sha1 {
                            " (default)"
                        } else {
                            ""
                        }
                    ))
                    && o.put(&format!(
                        "  Minimum Salt Length: {}{}\n",
                        pss.salt_len,
                        if pss.salt_len == 20 { " (default)" } else { "" }
                    ))
                    && o.put(&format!(
                        "  Trailer Field: 0x{:x}{}\n",
                        pss.trailer,
                        if pss.trailer == 1 { " (default)" } else { "" }
                    ))
            }
        };
        if !ok {
            return 0;
        }
    }
    1
}

/// "no <name> key material available" (`PROV_R_MISSING_KEY`), from `lib`.
fn missing_key(lib: c_int, f: &str, name: &str) -> c_int {
    err::raise_with_text(
        lib,
        PROV_R_MISSING_KEY,
        f,
        &format!("no {name} key material available"),
    );
    0
}

/// `ossl_ml_kem_key_to_text`: the private key's seed and dk (when asked for and there), then
/// the public key's ek.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an ML-KEM key.
pub(super) unsafe fn ml_kem_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    const F: &str = "ossl_ml_kem_key_to_text";
    let o = Out(out);
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { super::ml_kem_kmgmt::key(key) }) else {
        err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let name = k.variant.name();
    let (seed, dk, ek) = {
        let m = k.lock();
        (
            m.private().and_then(|p| p.seed()),
            m.private().map(|p| p.encode()),
            m.public().map(|p| p.encode()),
        )
    };
    let mut ret = 0;
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 && (dk.is_some() || seed.is_some()) {
        if !o.put(&format!("{name} Private-Key:\n")) {
            return 0;
        }
        if seed.as_deref().is_some_and(|s| !labeled_buf(o, "seed:", s))
            || dk.as_deref().is_some_and(|d| !labeled_buf(o, "dk:", d))
        {
            return 0;
        }
        ret = 1;
    }
    if let Some(ek) = ek {
        if ret == 0 && !o.put(&format!("{name} Public-Key:\n")) {
            return 0;
        }
        if !labeled_buf(o, "ek:", &ek) {
            return 0;
        }
        ret = 1;
    }
    if ret == 0 {
        return missing_key(ERR_LIB_PROV, F, name);
    }
    ret
}

/// `ossl_ml_dsa_key_to_text`: the private key's seed and encoding (when asked for), then the
/// public key.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an ML-DSA key.
pub(super) unsafe fn ml_dsa_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    const F: &str = "ossl_ml_dsa_key_to_text";
    let o = Out(out);
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { super::ml_dsa_kmgmt::key(key) }) else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let name = k.variant.name();
    let (seed, sk, pk) = {
        let m = k.lock();
        (
            m.private().and_then(|p| {
                p.seed()
                    .map(|s| rustyssl_crypto::bn::Zeroizing::new(s.to_vec()))
            }),
            m.private()
                .map(|p| rustyssl_crypto::bn::Zeroizing::new(p.encoding().to_vec())),
            m.public().map(|p| p.encode().to_vec()),
        )
    };
    let Some(pk) = pk else {
        return missing_key(ERR_LIB_PROV, F, name);
    };
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        let Some(sk) = sk else {
            return missing_key(ERR_LIB_PROV, F, name);
        };
        if !o.put(&format!("{name} Private-Key:\n"))
            || seed.as_deref().is_some_and(|s| !labeled_buf(o, "seed:", s))
            || !labeled_buf(o, "priv:", &sk)
        {
            return 0;
        }
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0
        && !o.put(&format!("{name} Public-Key:\n"))
    {
        return 0;
    }
    c_int::from(labeled_buf(o, "pub:", &pk))
}

/// `ossl_slh_dsa_key_to_text`: the private key (when asked for), then the public key.
///
/// # Safety
/// `out` is a live BIO; `key` is NULL or an SLH-DSA key.
pub(super) unsafe fn slh_dsa_to_text(out: *mut BIO, key: *const c_void, selection: c_int) -> c_int {
    const F: &str = "ossl_slh_dsa_key_to_text";
    let o = Out(out);
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { super::slh_dsa_kmgmt::key(key) }) else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let name = k.variant.name();
    let (sk, pk) = {
        let m = k.lock();
        (
            m.private()
                .map(|p| rustyssl_crypto::bn::Zeroizing::new(p.encoding().to_vec())),
            m.public().map(|p| p.encoding().to_vec()),
        )
    };
    let Some(pk) = pk else {
        return missing_key(ERR_LIB_PROV, F, name);
    };
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        let Some(sk) = sk else {
            return missing_key(ERR_LIB_PROV, F, name);
        };
        if !o.put(&format!("{name} Private-Key:\n")) || !labeled_buf(o, "priv:", &sk) {
            return 0;
        }
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0
        && !o.put(&format!("{name} Public-Key:\n"))
    {
        return 0;
    }
    c_int::from(labeled_buf(o, "pub:", &pk))
}
