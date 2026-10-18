//! The key types' envelope parameters (`cms_dh.c`, `cms_ec.c`, and the envelope half of
//! `cms_rsa.c`): X9.42 and X9.63 key derivation for key agreement, and RSAES-OAEP for key
//! transport.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING,
    ASN1_STRING_FLAG_BITS_LEFT, BIGNUM, CMS_R_DECODE_ERROR, CMS_R_INVALID_LABEL,
    CMS_R_INVALID_OAEP_PARAMETERS, CMS_R_KDF_PARAMETER_ERROR, CMS_R_PEER_KEY_ERROR,
    CMS_R_SHARED_INFO_ERROR, CMS_R_UNSUPPORTED_ENCRYPTION_TYPE, CMS_R_UNSUPPORTED_LABEL_SOURCE,
    EVP_CIPH_WRAP_MODE, EVP_CIPHER, EVP_MD, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_DH_KDF_NONE,
    EVP_PKEY_DH_KDF_X9_42, EVP_PKEY_ECDH_KDF_NONE, EVP_PKEY_ECDH_KDF_X9_63,
    NID_X9_62_id_ecPublicKey, NID_dh_cofactor_kdf, NID_dh_std_kdf, NID_dhpublicnumber,
    NID_id_smime_alg_ESDH, NID_pSpecified, NID_rsaEncryption, NID_rsaesOaep, NID_sha1, NID_undef,
    OSSL_DECODER_CTX, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_LIB_CTX, OSSL_PKEY_PARAM_PUB_KEY,
    RSA_OAEP_PARAMS, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, V_ASN1_NULL, V_ASN1_OBJECT,
    V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_UNDEF, X509_ALGOR,
};

use super::base::{CMS_SharedInfo_encode, nid_obj, raise};
use super::kari::orig_pubkey;
use super::{KeyAgreeRecipientInfo, KeyTransRecipientInfo};
use crate::asn1::any::ASN1_TYPE_get;
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_free,
    ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::asn1::tpl::items::{
    ASN1_TYPE_free, ASN1_TYPE_new, X509_ALGOR_free, X509_ALGOR_new, d2i_ASN1_INTEGER,
    d2i_X509_ALGOR, i2d_ASN1_INTEGER, i2d_X509_ALGOR,
};
use crate::asn1::tpl::util::{ASN1_TYPE_unpack_sequence, ASN1_item_pack};
use crate::bn::BN_free;
use crate::bn::conv::{ASN1_INTEGER_to_BN, BN_bn2binpad, BN_to_ASN1_INTEGER};
use crate::decoder::ctx::{OSSL_DECODER_CTX_free, OSSL_DECODER_from_data};
use crate::decoder::pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode, EVP_CIPHER_get_type,
};
use crate::evp::cipher_asn1::{EVP_CIPHER_asn1_to_param, EVP_CIPHER_param_to_asn1};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get0_cipher, EVP_EncryptInit_ex,
};
use crate::evp::digest::EVP_MD_get_type;
use crate::evp::exchange::EVP_PKEY_derive_set_peer;
use crate::evp::legacy_md::{EVP_get_digestbyname, EVP_sha1};
use crate::evp::pkey::params::{
    EVP_PKEY_get_bn_param, EVP_PKEY_get1_encoded_public_key, EVP_PKEY_set1_encoded_public_key,
};
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_get_size, EVP_PKEY_is_a, EVP_PKEY_new,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_get0_libctx, EVP_PKEY_CTX_get0_peerkey, EVP_PKEY_CTX_get0_pkey,
    EVP_PKEY_CTX_get0_propq, EVP_PKEY_CTX_new_from_name, EVP_PKEY_paramgen, EVP_PKEY_paramgen_init,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_get_dh_kdf_md, EVP_PKEY_CTX_get_dh_kdf_type, EVP_PKEY_CTX_get_ecdh_cofactor_mode,
    EVP_PKEY_CTX_get_ecdh_kdf_md, EVP_PKEY_CTX_get_ecdh_kdf_type, EVP_PKEY_CTX_get_rsa_mgf1_md,
    EVP_PKEY_CTX_get_rsa_oaep_md, EVP_PKEY_CTX_get_rsa_padding, EVP_PKEY_CTX_get0_rsa_oaep_label,
    EVP_PKEY_CTX_set_dh_kdf_md, EVP_PKEY_CTX_set_dh_kdf_outlen, EVP_PKEY_CTX_set_dh_kdf_type,
    EVP_PKEY_CTX_set_ecdh_cofactor_mode, EVP_PKEY_CTX_set_ecdh_kdf_md,
    EVP_PKEY_CTX_set_ecdh_kdf_outlen, EVP_PKEY_CTX_set_ecdh_kdf_type, EVP_PKEY_CTX_set_group_name,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set0_dh_kdf_oid, EVP_PKEY_CTX_set0_dh_kdf_ukm, EVP_PKEY_CTX_set0_ecdh_kdf_ukm,
    EVP_PKEY_CTX_set0_rsa_oaep_label,
};
use crate::mem;
use crate::objects::sigid::{OBJ_find_sigid_algs, OBJ_find_sigid_by_algs};
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::rsa_asn1::{RSA_OAEP_PARAMS_free, RSA_OAEP_PARAMS_it, RSA_OAEP_PARAMS_new};
use crate::rsa_pmeth::{algor_from_md, algor_from_nid, md_of_algor, mgf1_decode, mgf1_from_md};
use crate::x509::algor::{X509_ALGOR_get0, X509_ALGOR_set0};

/// `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

/// An AlgorithmIdentifier's object, parameter type, and parameter.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
unsafe fn algor_parts(alg: *const X509_ALGOR) -> (*const ASN1_OBJECT, c_int, *const c_void) {
    let mut aoid: *const ASN1_OBJECT = ptr::null();
    let mut atype: c_int = V_ASN1_UNDEF;
    let mut aval: *const c_void = ptr::null();
    // SAFETY: room for each; the caller's AlgorithmIdentifier.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut atype, &mut aval, alg) };
    (aoid, atype, aval)
}

/// A string's octets, empty for NULL.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn string_octets<'a>(s: *const ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    unsafe { super::base::octets(s.cast()) }
}

/// The name of an object, NUL-terminated; `None` if it has none.
fn name_of(obj: *const ASN1_OBJECT) -> Option<[c_char; NAME_LEN]> {
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for the name; the object, or NULL.
    (unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, obj, 0) } > 0).then_some(name)
}

/// `EVP_get_digestbynid`.
fn digest_by_nid(nid: c_int) -> *const EVP_MD {
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: NULL or a static name.
    unsafe { EVP_get_digestbyname(sn) }
}

/// `ossl_asn1_string_set_bits_left`.
fn set_bits_left(s: *mut ASN1_BIT_STRING, num: u8) {
    // SAFETY: a live string.
    let s = unsafe { &mut *s };
    s.flags &= !0x07;
    s.flags |=
        core::ffi::c_long::from(ASN1_STRING_FLAG_BITS_LEFT) | core::ffi::c_long::from(num & 0x07);
}

/// A copy of the user keying material from CRYPTO_malloc (NULL and 0 for none), or `None`.
fn ukm_copy(ukm: *const ASN1_OCTET_STRING) -> Option<(*mut u8, c_int)> {
    if ukm.is_null() {
        return Some((ptr::null_mut(), 0));
    }
    // SAFETY: a live string.
    let data = unsafe { super::base::octets(ukm) };
    let n = c_int::try_from(data.len()).ok()?;
    let p = super::enc::c_copy(data);
    (!p.is_null() || data.is_empty()).then_some((p, n))
}

/// The wrap cipher an AlgorithmIdentifier's parameter names, in the recipient's cipher
/// context (with its parameters), and its key length.
///
/// # Safety
/// `pctx` is a live context; `parameter` the SEQUENCE's string.
unsafe fn kek_from_parameter(
    pctx: *mut EVP_PKEY_CTX,
    k: &mut KeyAgreeRecipientInfo,
    parameter: *const c_void,
    for_dh: bool,
) -> Option<(*mut X509_ALGOR, *mut EVP_CIPHER, c_int)> {
    // SAFETY: the caller's guarantee.
    let der = unsafe { string_octets(parameter.cast()) };
    let mut p = der.as_ptr();
    let plen = core::ffi::c_long::try_from(der.len()).ok()?;
    // SAFETY: the DER's octets.
    let kekalg = unsafe { d2i_X509_ALGOR(ptr::null_mut(), &mut p, plen) };
    let mut kekcipher: *mut EVP_CIPHER = ptr::null_mut();
    let out = 'err: {
        // SAFETY: the decoded AlgorithmIdentifier, or NULL.
        let Some(ka) = (unsafe { kekalg.as_ref() }) else {
            break 'err None;
        };
        let kekctx = k.ctx;
        if kekctx.is_null() {
            break 'err None;
        }
        let name = if for_dh {
            let Some(n) = name_of(ka.algorithm) else {
                break 'err None;
            };
            n
        } else {
            name_of(ka.algorithm).unwrap_or([0; NAME_LEN])
        };
        // SAFETY: the context.
        let libctx: *mut OSSL_LIB_CTX = unsafe { EVP_PKEY_CTX_get0_libctx(pctx) };
        // SAFETY: as above.
        let propq = unsafe { EVP_PKEY_CTX_get0_propq(pctx) };
        // SAFETY: the name; the context's parts.
        kekcipher = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
        // SAFETY: a live cipher.
        if kekcipher.is_null() || unsafe { EVP_CIPHER_get_mode(kekcipher) } != EVP_CIPH_WRAP_MODE {
            break 'err None;
        }
        // SAFETY: the recipient's cipher context; the wrap.
        if unsafe {
            EVP_EncryptInit_ex(kekctx, kekcipher, ptr::null_mut(), ptr::null(), ptr::null())
        } == 0
        {
            break 'err None;
        }
        // SAFETY: as above; the parameters, or NULL.
        if unsafe { EVP_CIPHER_asn1_to_param(kekctx, ka.parameter) } <= 0 {
            break 'err None;
        }
        // SAFETY: as above.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(kekctx) };
        Some((kekalg, kekcipher, keylen))
    };
    if out.is_none() {
        // SAFETY: the cipher fetched here, or NULL.
        unsafe { EVP_CIPHER_free(kekcipher) };
        // SAFETY: the AlgorithmIdentifier decoded here, or NULL.
        unsafe { X509_ALGOR_free(kekalg) };
    }
    out
}

/// The recipient's wrap as an AlgorithmIdentifier (its parameters absent when it has none)
/// and its key length.
fn wrap_algor(k: &KeyAgreeRecipientInfo) -> Option<(*mut X509_ALGOR, c_int)> {
    let ctx = k.ctx;
    // SAFETY: the recipient's cipher context.
    let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    // SAFETY: its cipher, or NULL.
    let wrap_nid = if c.is_null() {
        NID_undef
    } else {
        // SAFETY: its cipher.
        unsafe { EVP_CIPHER_get_type(c) }
    };
    // SAFETY: as above.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    // SAFETY: no preconditions.
    let wrap_alg = unsafe { X509_ALGOR_new() };
    let ok = 'err: {
        // SAFETY: the new AlgorithmIdentifier, or NULL.
        let Some(w) = (unsafe { wrap_alg.as_mut() }) else {
            break 'err false;
        };
        w.algorithm = nid_obj(wrap_nid);
        // SAFETY: no preconditions.
        w.parameter = unsafe { ASN1_TYPE_new() };
        if w.parameter.is_null() {
            break 'err false;
        }
        // SAFETY: the context; the new parameter.
        if unsafe { EVP_CIPHER_param_to_asn1(ctx, w.parameter) } <= 0 {
            break 'err false;
        }
        // SAFETY: as above.
        if unsafe { ASN1_TYPE_get(w.parameter) } == NID_undef {
            // SAFETY: as above.
            unsafe { ASN1_TYPE_free(w.parameter) };
            w.parameter = ptr::null_mut();
        }
        true
    };
    if !ok {
        // SAFETY: the AlgorithmIdentifier made here, or NULL.
        unsafe { X509_ALGOR_free(wrap_alg) };
        return None;
    }
    Some((wrap_alg, keylen))
}

/// The wrap's AlgorithmIdentifier, encoded, as the key-encryption algorithm `kdf_nid`'s
/// parameter.
///
/// # Safety
/// `talg` and `wrap_alg` are live AlgorithmIdentifiers.
unsafe fn set_kdf_algor(talg: *mut X509_ALGOR, kdf_nid: c_int, wrap_alg: *mut X509_ALGOR) -> bool {
    let mut penc: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's AlgorithmIdentifier; room for the encoding.
    let penclen = unsafe { i2d_X509_ALGOR(wrap_alg, &mut penc) };
    if penclen <= 0 {
        // SAFETY: the encoding, or NULL.
        unsafe { mem::release(penc.cast()) };
        return false;
    }
    // SAFETY: no preconditions.
    let wrap_str = unsafe { ASN1_STRING_new() };
    if wrap_str.is_null() {
        // SAFETY: as above.
        unsafe { mem::release(penc.cast()) };
        return false;
    }
    // SAFETY: the new string, taking the encoding.
    unsafe { ASN1_STRING_set0(wrap_str, penc.cast(), penclen) };
    // SAFETY: the caller's AlgorithmIdentifier; a static object; the string.
    let rv = unsafe { X509_ALGOR_set0(talg, nid_obj(kdf_nid), V_ASN1_SEQUENCE, wrap_str.cast()) };
    if rv == 0 {
        // SAFETY: the string, not taken.
        unsafe { ASN1_STRING_free(wrap_str) };
    }
    rv != 0
}

// ECDH

/// `pkey_type2param`: a key of the parameters an AlgorithmIdentifier gives (a SEQUENCE of
/// explicit parameters or a curve's OID), or NULL.
///
/// # Safety
/// `pval` is what `X509_ALGOR_get0` gives for `ptype`.
unsafe fn pkey_type2param(
    ptype: c_int,
    pval: *const c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    const F: &str = "pkey_type2param";
    let mut pkey: *mut EVP_PKEY = ptr::null_mut();
    if ptype == V_ASN1_SEQUENCE {
        // SAFETY: the parameter's string.
        let der = unsafe { string_octets(pval.cast()) };
        let mut pm = der.as_ptr();
        let mut pmlen = der.len();
        // SAFETY: room for the key; static names; the context's parts.
        let ctx: *mut OSSL_DECODER_CTX = unsafe {
            OSSL_DECODER_CTX_new_for_pkey(
                &mut pkey,
                c"DER".as_ptr(),
                ptr::null(),
                c"EC".as_ptr(),
                OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                libctx,
                propq,
            )
        };
        if ctx.is_null() {
            // SAFETY: the key, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return ptr::null_mut();
        }
        // SAFETY: a live decoder; the parameters' octets.
        let ok = unsafe { OSSL_DECODER_from_data(ctx, &mut pm, &mut pmlen) } != 0;
        // SAFETY: the decoder made here.
        unsafe { OSSL_DECODER_CTX_free(ctx) };
        if !ok {
            raise(CMS_R_DECODE_ERROR, F);
            // SAFETY: as above.
            unsafe { EVP_PKEY_free(pkey) };
            return ptr::null_mut();
        }
        return pkey;
    }
    if ptype == V_ASN1_OBJECT {
        // SAFETY: a static name; the context's parts.
        let pctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"EC".as_ptr(), propq) };
        let ok = 'err: {
            // SAFETY: a live context.
            if pctx.is_null() || unsafe { EVP_PKEY_paramgen_init(pctx) } <= 0 {
                break 'err false;
            }
            let group = name_of(pval.cast());
            // SAFETY: as above; the curve's name.
            if group.is_none_or(|g| unsafe { EVP_PKEY_CTX_set_group_name(pctx, g.as_ptr()) } <= 0) {
                raise(CMS_R_DECODE_ERROR, F);
                break 'err false;
            }
            // SAFETY: as above; room for the key.
            (unsafe { EVP_PKEY_paramgen(pctx, &mut pkey) }) > 0
        };
        // SAFETY: the context made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        if !ok {
            // SAFETY: the key, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return ptr::null_mut();
        }
        return pkey;
    }
    raise(CMS_R_DECODE_ERROR, F);
    ptr::null_mut()
}

/// `ecdh_cms_set_peerkey`: the originator's public key as the derivation's peer.
///
/// # Safety
/// `pctx` is a live context; `alg` and `pubkey` live.
unsafe fn ecdh_set_peerkey(
    pctx: *mut EVP_PKEY_CTX,
    alg: *mut X509_ALGOR,
    pubkey: *mut ASN1_BIT_STRING,
) -> bool {
    // SAFETY: the caller's guarantee.
    let (aoid, atype, aval) = unsafe { algor_parts(alg) };
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(aoid) } != NID_X9_62_id_ecPublicKey {
        return false;
    }
    let pkpeer = if atype == V_ASN1_UNDEF || atype == V_ASN1_NULL {
        // Absent parameters: the group of our own key.
        // SAFETY: the caller's context.
        let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
        if pk.is_null() {
            return false;
        }
        // SAFETY: no preconditions.
        let peer = unsafe { EVP_PKEY_new() };
        // SAFETY: the new key; our key.
        if peer.is_null() || unsafe { EVP_PKEY_copy_parameters(peer, pk) } == 0 {
            // SAFETY: the key made here, or NULL.
            unsafe { EVP_PKEY_free(peer) };
            return false;
        }
        peer
    } else {
        // SAFETY: the caller's context.
        let libctx = unsafe { EVP_PKEY_CTX_get0_libctx(pctx) };
        // SAFETY: as above.
        let propq = unsafe { EVP_PKEY_CTX_get0_propq(pctx) };
        // SAFETY: the parameter, of its type.
        let peer = unsafe { pkey_type2param(atype, aval, libctx, propq) };
        if peer.is_null() {
            return false;
        }
        peer
    };
    // SAFETY: the caller's string.
    let p = unsafe { string_octets(pubkey.cast()) };
    let rv = !p.is_empty()
        // SAFETY: the peer key; the encoded point.
        && unsafe { EVP_PKEY_set1_encoded_public_key(pkpeer, p.as_ptr(), p.len()) } > 0
        // SAFETY: the context; the peer key.
        && unsafe { EVP_PKEY_derive_set_peer(pctx, pkpeer) } > 0;
    // SAFETY: the key made here; the context holds its own reference.
    unsafe { EVP_PKEY_free(pkpeer) };
    rv
}

/// `ecdh_cms_set_kdf_param`: the KDF's cofactor mode, type, and digest from the
/// key-encryption algorithm's NID.
fn ecdh_set_kdf_param(pctx: *mut EVP_PKEY_CTX, eckdf_nid: c_int) -> bool {
    if eckdf_nid == NID_undef {
        return false;
    }
    let (mut kdfmd_nid, mut kdf_nid) = (NID_undef, NID_undef);
    // SAFETY: room for each.
    if unsafe { OBJ_find_sigid_algs(eckdf_nid, &mut kdfmd_nid, &mut kdf_nid) } == 0 {
        return false;
    }
    let cofactor = match kdf_nid {
        n if n == NID_dh_std_kdf => 0,
        n if n == NID_dh_cofactor_kdf => 1,
        _ => return false,
    };
    // SAFETY: a live context.
    if unsafe { EVP_PKEY_CTX_set_ecdh_cofactor_mode(pctx, cofactor) } <= 0 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_X9_63) } <= 0 {
        return false;
    }
    let kdf_md = digest_by_nid(kdfmd_nid);
    // SAFETY: as above; a built-in digest.
    !kdf_md.is_null() && unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) } > 0
}

/// `ecdh_cms_set_shared_info`: the KDF from the key-encryption algorithm, the wrap from its
/// parameter, and the ECC-CMS-SharedInfo as the KDF's input.
///
/// # Safety
/// `pctx` is the recipient's live context.
unsafe fn ecdh_set_shared_info(pctx: *mut EVP_PKEY_CTX, k: &mut KeyAgreeRecipientInfo) -> bool {
    let alg = k.key_encryption_algorithm;
    let ukm = k.ukm;
    // SAFETY: the recipient's algorithm, made with it.
    let (aoid, ptype, parameter) = unsafe { algor_parts(alg) };
    // SAFETY: its object.
    if !ecdh_set_kdf_param(pctx, unsafe { OBJ_obj2nid(aoid) }) {
        raise(CMS_R_KDF_PARAMETER_ERROR, "ecdh_cms_set_shared_info");
        return false;
    }
    if ptype != V_ASN1_SEQUENCE {
        return false;
    }
    // SAFETY: the caller's context; the SEQUENCE's string.
    let Some((kekalg, kekcipher, keylen)) =
        (unsafe { kek_from_parameter(pctx, k, parameter, false) })
    else {
        return false;
    };
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: the context.
    let ok = unsafe { EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) } > 0 && {
        // SAFETY: room for the encoding; the wrap's AlgorithmIdentifier; the keying material.
        let plen = unsafe { CMS_SharedInfo_encode(&mut der, kekalg, ukm, keylen) };
        // SAFETY: the context, taking the encoding.
        plen > 0 && unsafe { EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, der, plen) } > 0 && {
            der = ptr::null_mut();
            true
        }
    };
    // SAFETY: the cipher fetched for it.
    unsafe { EVP_CIPHER_free(kekcipher) };
    // SAFETY: the AlgorithmIdentifier decoded for it.
    unsafe { X509_ALGOR_free(kekalg) };
    // SAFETY: the encoding, if not taken, or NULL.
    unsafe { mem::release(der.cast()) };
    ok
}

/// `ecdh_cms_decrypt`.
fn ecdh_decrypt(k: &mut KeyAgreeRecipientInfo) -> c_int {
    let pctx = k.pctx;
    if pctx.is_null() {
        return 0;
    }
    // See if the peer key is needed.
    // SAFETY: a live context.
    if unsafe { EVP_PKEY_CTX_get0_peerkey(pctx) }.is_null() {
        let Some((alg, pubkey)) = orig_pubkey(k) else {
            return 0;
        };
        if alg.is_null() || pubkey.is_null() {
            return 0;
        }
        // SAFETY: as above; the originator's algorithm and key.
        if !unsafe { ecdh_set_peerkey(pctx, alg, pubkey) } {
            raise(CMS_R_PEER_KEY_ERROR, "ecdh_cms_decrypt");
            return 0;
        }
    }
    // SAFETY: as above.
    if !unsafe { ecdh_set_shared_info(pctx, k) } {
        raise(CMS_R_SHARED_INFO_ERROR, "ecdh_cms_decrypt");
        return 0;
    }
    1
}

/// `ecdh_cms_encrypt`: the ephemeral public key into the originator, then the KDF (X9.63,
/// SHA-1 by default) and wrap as the key-encryption algorithm.
fn ecdh_encrypt(k: &mut KeyAgreeRecipientInfo) -> c_int {
    let pctx = k.pctx;
    if pctx.is_null() {
        return 0;
    }
    // The ephemeral key.
    // SAFETY: a live context.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    let Some((talg, pubkey)) = orig_pubkey(k) else {
        return 0;
    };
    if talg.is_null() || pubkey.is_null() {
        return 0;
    }
    // SAFETY: the originator's AlgorithmIdentifier, live.
    let (aoid, _, _) = unsafe { algor_parts(talg) };
    // Is everything uninitialized?
    if aoid == nid_obj(NID_undef).cast_const() {
        let mut penc: *mut u8 = ptr::null_mut();
        // SAFETY: the ephemeral key; room for its encoding.
        let enckeylen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey, &mut penc) };
        let Some(n) = c_int::try_from(enckeylen).ok().filter(|&n| n > 0) else {
            // SAFETY: the encoding, or NULL.
            unsafe { mem::release(penc.cast()) };
            return 0;
        };
        // SAFETY: the originator's key, taking the encoding.
        unsafe { ASN1_STRING_set0(pubkey.cast(), penc.cast(), n) };
        set_bits_left(pubkey, 0);
        // SAFETY: the AlgorithmIdentifier; a static object.
        unsafe {
            X509_ALGOR_set0(
                talg,
                nid_obj(NID_X9_62_id_ecPublicKey),
                V_ASN1_UNDEF,
                ptr::null_mut(),
            )
        };
    }
    // See if custom parameters are set.
    // SAFETY: a live context.
    let kdf_type = unsafe { EVP_PKEY_CTX_get_ecdh_kdf_type(pctx) };
    if kdf_type <= 0 {
        return 0;
    }
    let mut kdf_md: *const EVP_MD = ptr::null();
    // SAFETY: as above; room for the digest.
    if unsafe { EVP_PKEY_CTX_get_ecdh_kdf_md(pctx, &mut kdf_md) } <= 0 {
        return 0;
    }
    // SAFETY: as above.
    let ecdh_nid = match unsafe { EVP_PKEY_CTX_get_ecdh_cofactor_mode(pctx) } {
        n if n < 0 => return 0,
        0 => NID_dh_std_kdf,
        1 => NID_dh_cofactor_kdf,
        n => n,
    };
    if kdf_type != EVP_PKEY_ECDH_KDF_NONE {
        // An unknown KDF.
        return 0;
    }
    // SAFETY: as above.
    if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_X9_63) } <= 0 {
        return 0;
    }
    if kdf_md.is_null() {
        // SAFETY: no preconditions.
        kdf_md = unsafe { EVP_sha1() };
        // SAFETY: as above; a built-in digest.
        if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) } <= 0 {
            return 0;
        }
    }
    let talg = k.key_encryption_algorithm;
    let ukm = k.ukm;
    let mut kdf_nid = NID_undef;
    // SAFETY: a live digest.
    let md_nid = unsafe { EVP_MD_get_type(kdf_md) };
    // SAFETY: room for the NID.
    if unsafe { OBJ_find_sigid_by_algs(&mut kdf_nid, md_nid, ecdh_nid) } == 0 {
        return 0;
    }
    let Some((wrap_alg, keylen)) = wrap_algor(k) else {
        return 0;
    };
    let mut penc: *mut c_uchar = ptr::null_mut();
    // SAFETY: the context.
    let rv = unsafe { EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) } > 0 && {
        // SAFETY: room for the encoding; the wrap's AlgorithmIdentifier; the keying material.
        let penclen = unsafe { CMS_SharedInfo_encode(&mut penc, wrap_alg, ukm, keylen) };
        // SAFETY: the context, taking the encoding.
        penclen > 0 && unsafe { EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, penc, penclen) } > 0 && {
            penc = ptr::null_mut();
            // SAFETY: the recipient's algorithm; the wrap's.
            unsafe { set_kdf_algor(talg, kdf_nid, wrap_alg) }
        }
    };
    // SAFETY: the encoding, if not taken, or NULL.
    unsafe { mem::release(penc.cast()) };
    // SAFETY: the AlgorithmIdentifier made for it.
    unsafe { X509_ALGOR_free(wrap_alg) };
    c_int::from(rv)
}

/// `ossl_cms_ecdh_envelope`: the KDF's parameters for decrypting (`cmd` 1) or encrypting.
pub(crate) fn ecdh_envelope(k: &mut KeyAgreeRecipientInfo, cmd: c_int) -> c_int {
    if cmd == 1 {
        ecdh_decrypt(k)
    } else {
        ecdh_encrypt(k)
    }
}

// DH

/// `dh_cms_set_peerkey`: the originator's public key (an INTEGER, padded to the prime's
/// size) as the derivation's peer.
///
/// # Safety
/// `pctx` is a live context; `alg` and `pubkey` live.
unsafe fn dh_set_peerkey(
    pctx: *mut EVP_PKEY_CTX,
    alg: *mut X509_ALGOR,
    pubkey: *mut ASN1_BIT_STRING,
) -> bool {
    // SAFETY: the caller's guarantee.
    let (aoid, atype, _) = unsafe { algor_parts(alg) };
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(aoid) } != NID_dhpublicnumber {
        return false;
    }
    // Only absent parameters are allowed.
    if atype != V_ASN1_UNDEF && atype != V_ASN1_NULL {
        return false;
    }
    // SAFETY: the caller's context.
    let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: its key.
    if pk.is_null() || unsafe { EVP_PKEY_is_a(pk, c"DHX".as_ptr()) } == 0 {
        return false;
    }
    // SAFETY: the caller's string.
    let der = unsafe { string_octets(pubkey.cast()) };
    if der.is_empty() {
        return false;
    }
    let mut p = der.as_ptr();
    let Ok(plen) = core::ffi::c_long::try_from(der.len()) else {
        return false;
    };
    // SAFETY: the INTEGER's octets.
    let public_key: *mut ASN1_INTEGER = unsafe { d2i_ASN1_INTEGER(ptr::null_mut(), &mut p, plen) };
    let mut bnpub: *mut BIGNUM = ptr::null_mut();
    let mut pkpeer: *mut EVP_PKEY = ptr::null_mut();
    let rv = 'err: {
        if public_key.is_null() {
            break 'err false;
        }
        // Padded to the prime's size, as the encoded public key must be.
        // SAFETY: our key.
        let Some(size) = usize::try_from(unsafe { EVP_PKEY_get_size(pk) }).ok() else {
            break 'err false;
        };
        // SAFETY: the decoded INTEGER.
        bnpub = unsafe { ASN1_INTEGER_to_BN(public_key, ptr::null_mut()) };
        if bnpub.is_null() {
            break 'err false;
        }
        let mut buf = vec![0u8; size];
        let Ok(n) = c_int::try_from(size) else {
            break 'err false;
        };
        // SAFETY: the number; room for `n` octets.
        if unsafe { BN_bn2binpad(bnpub, buf.as_mut_ptr(), n) } < 0 {
            break 'err false;
        }
        // SAFETY: no preconditions.
        pkpeer = unsafe { EVP_PKEY_new() };
        if pkpeer.is_null()
            // SAFETY: the new key; our key.
            || unsafe { EVP_PKEY_copy_parameters(pkpeer, pk) } == 0
            // SAFETY: the new key; the public key's octets.
            || unsafe { EVP_PKEY_set1_encoded_public_key(pkpeer, buf.as_ptr(), buf.len()) } <= 0
        {
            break 'err false;
        }
        // SAFETY: the context; the peer key.
        (unsafe { EVP_PKEY_derive_set_peer(pctx, pkpeer) }) > 0
    };
    // SAFETY: the INTEGER decoded here, or NULL.
    unsafe { ASN1_INTEGER_free(public_key) };
    // SAFETY: the number made here, or NULL.
    unsafe { BN_free(bnpub) };
    // SAFETY: the key made here, or NULL.
    unsafe { EVP_PKEY_free(pkpeer) };
    rv
}

/// `dh_cms_set_shared_info`: X9.42's KDF with SHA-1, the wrap from the key-encryption
/// algorithm's parameter, and the keying material.
///
/// # Safety
/// `pctx` is the recipient's live context.
unsafe fn dh_set_shared_info(pctx: *mut EVP_PKEY_CTX, k: &mut KeyAgreeRecipientInfo) -> bool {
    let alg = k.key_encryption_algorithm;
    let ukm = k.ukm;
    // SAFETY: the recipient's algorithm, made with it.
    let (aoid, ptype, parameter) = unsafe { algor_parts(alg) };
    // For DH only one OID is allowed.
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(aoid) } != NID_id_smime_alg_ESDH {
        raise(CMS_R_KDF_PARAMETER_ERROR, "dh_cms_set_shared_info");
        return false;
    }
    // SAFETY: no preconditions.
    let sha1 = unsafe { EVP_sha1() };
    // SAFETY: the context.
    if unsafe { EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_X9_42) } <= 0
        // SAFETY: as above; a built-in digest.
        || unsafe { EVP_PKEY_CTX_set_dh_kdf_md(pctx, sha1) } <= 0
    {
        return false;
    }
    if ptype != V_ASN1_SEQUENCE {
        return false;
    }
    // SAFETY: the caller's context; the SEQUENCE's string.
    let Some((kekalg, kekcipher, keylen)) =
        (unsafe { kek_from_parameter(pctx, k, parameter, true) })
    else {
        return false;
    };
    // SAFETY: a live cipher.
    let kek_nid = unsafe { EVP_CIPHER_get_type(kekcipher) };
    let mut dukm: *mut u8 = ptr::null_mut();
    // SAFETY: the context.
    let ok = unsafe { EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) } > 0
        // A built-in object, not freed.
        // SAFETY: as above.
        && unsafe { EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, nid_obj(kek_nid)) } > 0
        && ukm_copy(ukm).is_some_and(|(p, n)| {
            dukm = p;
            // SAFETY: as above, taking the copy.
            (unsafe { EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, p, n) }) > 0 && {
                dukm = ptr::null_mut();
                true
            }
        });
    // SAFETY: the AlgorithmIdentifier decoded for it.
    unsafe { X509_ALGOR_free(kekalg) };
    // SAFETY: the cipher fetched for it.
    unsafe { EVP_CIPHER_free(kekcipher) };
    // SAFETY: the copy, if not taken, or NULL.
    unsafe { mem::release(dukm.cast()) };
    ok
}

/// `dh_cms_decrypt`.
fn dh_decrypt(k: &mut KeyAgreeRecipientInfo) -> c_int {
    let pctx = k.pctx;
    if pctx.is_null() {
        return 0;
    }
    // SAFETY: a live context.
    if unsafe { EVP_PKEY_CTX_get0_peerkey(pctx) }.is_null() {
        let Some((alg, pubkey)) = orig_pubkey(k) else {
            return 0;
        };
        if alg.is_null() || pubkey.is_null() {
            return 0;
        }
        // SAFETY: as above; the originator's algorithm and key.
        if !unsafe { dh_set_peerkey(pctx, alg, pubkey) } {
            raise(CMS_R_PEER_KEY_ERROR, "dh_cms_decrypt");
            return 0;
        }
    }
    // SAFETY: as above.
    if !unsafe { dh_set_shared_info(pctx, k) } {
        raise(CMS_R_SHARED_INFO_ERROR, "dh_cms_decrypt");
        return 0;
    }
    1
}

/// `dh_cms_encrypt`: the ephemeral public key (an INTEGER) into the originator, then X9.42's
/// KDF with SHA-1 and the wrap as ESDH's parameter.
fn dh_encrypt(k: &mut KeyAgreeRecipientInfo) -> c_int {
    let pctx = k.pctx;
    if pctx.is_null() {
        return 0;
    }
    // SAFETY: a live context.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    let Some((talg, pubkey)) = orig_pubkey(k) else {
        return 0;
    };
    if talg.is_null() || pubkey.is_null() {
        return 0;
    }
    // SAFETY: the originator's AlgorithmIdentifier, live.
    let (aoid, _, _) = unsafe { algor_parts(talg) };
    if aoid == nid_obj(NID_undef).cast_const() {
        let mut bn: *mut BIGNUM = ptr::null_mut();
        // SAFETY: the ephemeral key; a static name; room for the number.
        if unsafe { EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY.as_ptr(), &mut bn) } == 0 {
            return 0;
        }
        // SAFETY: the number.
        let pubk = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
        // SAFETY: the number made above.
        unsafe { BN_free(bn) };
        if pubk.is_null() {
            return 0;
        }
        let mut penc: *mut c_uchar = ptr::null_mut();
        // SAFETY: the INTEGER; room for its encoding.
        let penclen = unsafe { i2d_ASN1_INTEGER(pubk, &mut penc) };
        // SAFETY: the INTEGER made above.
        unsafe { ASN1_INTEGER_free(pubk) };
        if penclen <= 0 {
            // SAFETY: the encoding, or NULL.
            unsafe { mem::release(penc.cast()) };
            return 0;
        }
        // SAFETY: the originator's key, taking the encoding.
        unsafe { ASN1_STRING_set0(pubkey.cast(), penc.cast(), penclen) };
        set_bits_left(pubkey, 0);
        // SAFETY: the AlgorithmIdentifier; a static object.
        unsafe {
            X509_ALGOR_set0(
                talg,
                nid_obj(NID_dhpublicnumber),
                V_ASN1_UNDEF,
                ptr::null_mut(),
            )
        };
    }
    // SAFETY: a live context.
    let kdf_type = unsafe { EVP_PKEY_CTX_get_dh_kdf_type(pctx) };
    let mut kdf_md: *const EVP_MD = ptr::null();
    // SAFETY: as above; room for the digest.
    if kdf_type <= 0 || unsafe { EVP_PKEY_CTX_get_dh_kdf_md(pctx, &mut kdf_md) } <= 0 {
        return 0;
    }
    if kdf_type == EVP_PKEY_DH_KDF_NONE {
        // SAFETY: as above.
        if unsafe { EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_X9_42) } <= 0 {
            return 0;
        }
    } else if kdf_type != EVP_PKEY_DH_KDF_X9_42 {
        // An unknown KDF.
        return 0;
    }
    if kdf_md.is_null() {
        // Only SHA-1.
        // SAFETY: no preconditions.
        kdf_md = unsafe { EVP_sha1() };
        // SAFETY: as above; a built-in digest.
        if unsafe { EVP_PKEY_CTX_set_dh_kdf_md(pctx, kdf_md) } <= 0 {
            return 0;
        }
    // SAFETY: a live digest.
    } else if unsafe { EVP_MD_get_type(kdf_md) } != NID_sha1 {
        return 0;
    }
    let talg = k.key_encryption_algorithm;
    let ukm = k.ukm;
    // SAFETY: the recipient's cipher context.
    let c = unsafe { EVP_CIPHER_CTX_get0_cipher(k.ctx) };
    // SAFETY: its cipher, or NULL.
    let wrap_nid = if c.is_null() {
        NID_undef
    } else {
        // SAFETY: its cipher.
        unsafe { EVP_CIPHER_get_type(c) }
    };
    // SAFETY: the context; a built-in object.
    if unsafe { EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, nid_obj(wrap_nid)) } <= 0 {
        return 0;
    }
    let Some((wrap_alg, keylen)) = wrap_algor(k) else {
        return 0;
    };
    let mut dukm: *mut u8 = ptr::null_mut();
    // SAFETY: the context.
    let rv = unsafe { EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) } > 0
        && ukm_copy(ukm).is_some_and(|(p, n)| {
            dukm = p;
            // SAFETY: the context, taking the copy.
            (unsafe { EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, p, n) }) > 0 && {
                dukm = ptr::null_mut();
                true
            }
        })
        // SAFETY: the recipient's algorithm; the wrap's.
        && unsafe { set_kdf_algor(talg, NID_id_smime_alg_ESDH, wrap_alg) };
    // SAFETY: the AlgorithmIdentifier made for it.
    unsafe { X509_ALGOR_free(wrap_alg) };
    // SAFETY: the copy, if not taken, or NULL.
    unsafe { mem::release(dukm.cast()) };
    c_int::from(rv)
}

/// `ossl_cms_dh_envelope`: the KDF's parameters for decrypting (`cmd` 1) or encrypting.
pub(crate) fn dh_envelope(k: &mut KeyAgreeRecipientInfo, cmd: c_int) -> c_int {
    if cmd == 1 {
        dh_decrypt(k)
    } else {
        dh_encrypt(k)
    }
}

// RSA

/// `rsa_oaep_decode`: an AlgorithmIdentifier's RSAES-OAEP-params, with MGF1's digest
/// decoded, or NULL.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
unsafe fn rsa_oaep_decode(alg: &X509_ALGOR) -> *mut RSA_OAEP_PARAMS {
    // SAFETY: no preconditions.
    let it = unsafe { RSA_OAEP_PARAMS_it() };
    // SAFETY: its parameter, NULL or live.
    let oaep = unsafe { ASN1_TYPE_unpack_sequence(it, alg.parameter) }.cast::<RSA_OAEP_PARAMS>();
    // SAFETY: the decoded parameters, or NULL.
    let Some(o) = (unsafe { oaep.as_mut() }) else {
        return ptr::null_mut();
    };
    if !o.maskGenFunc.is_null() {
        // SAFETY: its MGF's AlgorithmIdentifier.
        o.maskHash = unsafe { mgf1_decode(o.maskGenFunc) };
        if o.maskHash.is_null() {
            // SAFETY: the parameters decoded here.
            unsafe { RSA_OAEP_PARAMS_free(oaep) };
            return ptr::null_mut();
        }
    }
    oaep
}

/// `rsa_cms_decrypt`: the key-encryption algorithm's OAEP parameters into the recipient's
/// context. -1 (on which, as in OpenSSL, the caller goes on) for parameters it can't use.
fn rsa_decrypt(k: &mut KeyTransRecipientInfo) -> c_int {
    const F: &str = "rsa_cms_decrypt";
    let pkctx = k.pctx;
    if pkctx.is_null() {
        return 0;
    }
    // SAFETY: the recipient's algorithm, made with it.
    let Some(cmsalg) = (unsafe { k.key_encryption_algorithm.as_ref() }) else {
        return -1;
    };
    // SAFETY: its object.
    let nid = unsafe { OBJ_obj2nid(cmsalg.algorithm) };
    if nid == NID_rsaEncryption {
        return 1;
    }
    if nid != NID_rsaesOaep {
        raise(CMS_R_UNSUPPORTED_ENCRYPTION_TYPE, F);
        return -1;
    }
    // SAFETY: as above.
    let oaep = unsafe { rsa_oaep_decode(cmsalg) };
    // SAFETY: the decoded parameters, or NULL.
    let Some(o) = (unsafe { oaep.as_ref() }) else {
        raise(CMS_R_INVALID_OAEP_PARAMETERS, F);
        return -1;
    };
    let rv = 'err: {
        // SAFETY: its MGF1 digest's AlgorithmIdentifier, or NULL.
        let mgf1md = unsafe { md_of_algor(o.maskHash) };
        if mgf1md.is_null() {
            break 'err -1;
        }
        // SAFETY: its digest's, or NULL.
        let md = unsafe { md_of_algor(o.hashFunc) };
        if md.is_null() {
            break 'err -1;
        }
        let mut label: &[u8] = &[];
        let mut has_label = false;
        if !o.pSourceFunc.is_null() {
            // SAFETY: its label source.
            let (aoid, ptype, parameter) = unsafe { algor_parts(o.pSourceFunc) };
            // SAFETY: its object.
            if unsafe { OBJ_obj2nid(aoid) } != NID_pSpecified {
                raise(CMS_R_UNSUPPORTED_LABEL_SOURCE, F);
                break 'err -1;
            }
            if ptype != V_ASN1_OCTET_STRING {
                raise(CMS_R_INVALID_LABEL, F);
                break 'err -1;
            }
            // SAFETY: the OCTET STRING.
            label = unsafe { string_octets(parameter.cast()) };
            has_label = true;
        }
        // SAFETY: the recipient's context.
        if unsafe { EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_OAEP_PADDING) } <= 0 {
            break 'err -1;
        }
        // SAFETY: as above; a live digest.
        if unsafe { EVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md) } <= 0 {
            break 'err -1;
        }
        // SAFETY: as above.
        if unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) } <= 0 {
            break 'err -1;
        }
        if has_label {
            let Ok(n) = c_int::try_from(label.len()) else {
                break 'err -1;
            };
            let dup = super::enc::c_copy(label);
            if dup.is_null() && !label.is_empty() {
                break 'err -1;
            }
            // SAFETY: as above, taking the copy.
            if unsafe { EVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, dup.cast(), n) } <= 0 {
                // SAFETY: the copy, not taken.
                unsafe { mem::release(dup.cast()) };
                break 'err -1;
            }
        }
        1
    };
    // SAFETY: the parameters decoded here.
    unsafe { RSA_OAEP_PARAMS_free(oaep) };
    rv
}

/// `rsa_cms_encrypt`: the key-encryption algorithm from the context's padding:
/// rsaEncryption, or RSAES-OAEP with its digests and label.
fn rsa_encrypt(k: &mut KeyTransRecipientInfo) -> c_int {
    let alg = k.key_encryption_algorithm;
    let pkctx = k.pctx;
    let mut pad_mode = RSA_PKCS1_PADDING;
    // SAFETY: the recipient's context; room for the padding.
    if !pkctx.is_null() && unsafe { EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
        return 0;
    }
    if pad_mode == RSA_PKCS1_PADDING {
        // SAFETY: the recipient's algorithm; a static object.
        return unsafe {
            X509_ALGOR_set0(
                alg,
                nid_obj(NID_rsaEncryption),
                V_ASN1_NULL,
                ptr::null_mut(),
            )
        };
    }
    // Nothing else is supported.
    if pad_mode != RSA_PKCS1_OAEP_PADDING {
        return 0;
    }
    let mut oaep: *mut RSA_OAEP_PARAMS = ptr::null_mut();
    let mut os: *mut ASN1_STRING = ptr::null_mut();
    let mut los: *mut ASN1_OCTET_STRING = ptr::null_mut();
    let rv = 'err: {
        let mut md: *const EVP_MD = ptr::null();
        let mut mgf1md: *const EVP_MD = ptr::null();
        // SAFETY: the context; room for the digest.
        if unsafe { EVP_PKEY_CTX_get_rsa_oaep_md(pkctx, &mut md) } <= 0 {
            break 'err 0;
        }
        // SAFETY: as above.
        if unsafe { EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mut mgf1md) } <= 0 {
            break 'err 0;
        }
        let mut label: *mut u8 = ptr::null_mut();
        // SAFETY: as above; room for the label.
        let labellen = unsafe { EVP_PKEY_CTX_get0_rsa_oaep_label(pkctx, &mut label) };
        if labellen < 0 {
            break 'err 0;
        }
        // SAFETY: no preconditions.
        oaep = unsafe { RSA_OAEP_PARAMS_new() };
        // SAFETY: the new parameters, or NULL.
        let Some(o) = (unsafe { oaep.as_mut() }) else {
            break 'err 0;
        };
        // SAFETY: its slot; a live digest.
        if !unsafe { algor_from_md(&mut o.hashFunc, md) }
            // SAFETY: as above.
            || !unsafe { mgf1_from_md(&mut o.maskGenFunc, mgf1md) }
        {
            break 'err 0;
        }
        if labellen > 0 {
            // SAFETY: no preconditions.
            los = unsafe { ASN1_OCTET_STRING_new() };
            // SAFETY: the new string; the context's label.
            if los.is_null() || unsafe { ASN1_OCTET_STRING_set(los, label, labellen) } == 0 {
                break 'err 0;
            }
            // SAFETY: the string, which the AlgorithmIdentifier takes.
            o.pSourceFunc =
                unsafe { algor_from_nid(NID_pSpecified, V_ASN1_OCTET_STRING, los.cast()) };
            if o.pSourceFunc.is_null() {
                break 'err 0;
            }
            los = ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { RSA_OAEP_PARAMS_it() };
        // The parameters' encoding.
        // SAFETY: the parameters; room for the string.
        if unsafe { ASN1_item_pack(oaep.cast(), it, &mut os) }.is_null() {
            break 'err 0;
        }
        // SAFETY: the recipient's algorithm; a static object; the string.
        if unsafe { X509_ALGOR_set0(alg, nid_obj(NID_rsaesOaep), V_ASN1_SEQUENCE, os.cast()) } == 0
        {
            break 'err 0;
        }
        os = ptr::null_mut();
        1
    };
    // SAFETY: the parameters made here, or NULL.
    unsafe { RSA_OAEP_PARAMS_free(oaep) };
    // SAFETY: the string, if not taken, or NULL.
    unsafe { ASN1_STRING_free(os) };
    // SAFETY: as above.
    unsafe { ASN1_STRING_free(los) };
    rv
}

/// `ossl_cms_rsa_envelope`: the OAEP parameters for decrypting (`cmd` 1) or encrypting.
pub(crate) fn rsa_envelope(k: &mut KeyTransRecipientInfo, cmd: c_int) -> c_int {
    if cmd == 1 {
        rsa_decrypt(k)
    } else {
        rsa_encrypt(k)
    }
}
