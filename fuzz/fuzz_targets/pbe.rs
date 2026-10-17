//! Fuzzes password-based decryption of untrusted parameters, as an EncryptedPrivateKeyInfo
//! brings them: an AlgorithmIdentifier decoded from the input, its PBE parameters (PBES2 with
//! PBKDF2 or scrypt, PKCS#12's, PBES1) through EVP_PBE_CipherInit with a password from the
//! input, then the rest of the input decrypted. Nothing may crash or read out of bounds (ASan).
//! Iteration counts and scrypt costs past small ones are skipped, to keep runs fast.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_ITEM, EVP_CIPHER_CTX, PBE2PARAM, PBKDF2PARAM, SCRYPT_PARAMS, X509_ALGOR};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_X509_ALGOR(a: *mut *mut X509_ALGOR, pp: *mut *const u8, len: c_long) -> *mut X509_ALGOR;
    fn X509_ALGOR_free(a: *mut X509_ALGOR);
    fn OBJ_obj2nid(o: *const c_void) -> c_int;
    fn ASN1_TYPE_unpack_sequence(it: *const ASN1_ITEM, t: *const c_void) -> *mut c_void;
    fn PBE2PARAM_it() -> *const ASN1_ITEM;
    fn PBKDF2PARAM_it() -> *const ASN1_ITEM;
    fn SCRYPT_PARAMS_it() -> *const ASN1_ITEM;
    fn PBE2PARAM_free(p: *mut PBE2PARAM);
    fn PBKDF2PARAM_free(p: *mut PBKDF2PARAM);
    fn SCRYPT_PARAMS_free(p: *mut SCRYPT_PARAMS);
    fn ASN1_INTEGER_get(a: *const c_void) -> c_long;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(c: *mut EVP_CIPHER_CTX);
    fn EVP_PBE_CipherInit(obj: *mut c_void, pass: *const c_char, passlen: c_int, param: *mut c_void, ctx: *mut EVP_CIPHER_CTX, en_de: c_int) -> c_int;
    fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    fn EVP_CipherFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    fn ERR_clear_error();
}

/// `NID_pbes2`, `NID_id_pbkdf2`, `NID_id_scrypt`, and the PBEPARAM-based PBEs' range.
const NID_PBES2: c_int = 161;
const NID_PBKDF2: c_int = 69;
const NID_SCRYPT: c_int = 973;

/// Whether the PBE's cost is small enough to run: PBKDF2's iterations, scrypt's N, r, and p,
/// and the PBEParameter's iterations (the INTEGER after the salt) bounded.
///
/// # Safety
/// `a` is a live AlgorithmIdentifier.
unsafe fn cheap(a: *const X509_ALGOR) -> bool {
    // SAFETY: the caller's guarantee; the decoded structures, freed here.
    unsafe {
        let nid = OBJ_obj2nid((*a).algorithm.cast());
        if nid != NID_PBES2 {
            // PBEPARAM { salt, iter }: PKCS#12's and PBES1's (or unknown, which fail early).
            return true;
        }
        let pbe2: *mut PBE2PARAM = ASN1_TYPE_unpack_sequence(PBE2PARAM_it(), (*a).parameter.cast()).cast();
        if pbe2.is_null() {
            return true;
        }
        let kf = (*pbe2).keyfunc;
        let ok = match OBJ_obj2nid((*kf).algorithm.cast()) {
            NID_PBKDF2 => {
                let k: *mut PBKDF2PARAM = ASN1_TYPE_unpack_sequence(PBKDF2PARAM_it(), (*kf).parameter.cast()).cast();
                let ok = k.is_null() || (1..=2000).contains(&ASN1_INTEGER_get((*k).iter.cast()));
                PBKDF2PARAM_free(k);
                ok
            }
            NID_SCRYPT => {
                let s: *mut SCRYPT_PARAMS = ASN1_TYPE_unpack_sequence(SCRYPT_PARAMS_it(), (*kf).parameter.cast()).cast();
                let ok = s.is_null()
                    || (ASN1_INTEGER_get((*s).costParameter.cast()) <= 1024
                        && ASN1_INTEGER_get((*s).blockSize.cast()) <= 8
                        && ASN1_INTEGER_get((*s).parallelizationParameter.cast()) <= 2);
                SCRYPT_PARAMS_free(s);
                ok
            }
            _ => true,
        };
        PBE2PARAM_free(pbe2);
        ok
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&passlen, rest)) = input.split_first() else { return };
    let passlen = usize::from(passlen % 32).min(rest.len());
    let (pass, rest) = rest.split_at(passlen);
    let Ok(len) = c_long::try_from(rest.len()) else { return };
    let mut p = rest.as_ptr();
    // SAFETY: the input's octets; the structures and context made here, freed once.
    unsafe {
        let a = d2i_X509_ALGOR(ptr::null_mut(), &mut p, len);
        if a.is_null() {
            ERR_clear_error();
            return;
        }
        let consumed = (p as usize).wrapping_sub(rest.as_ptr() as usize);
        let data = rest.get(consumed..).unwrap_or_default();
        if cheap(a) {
            let ctx = EVP_CIPHER_CTX_new();
            let plen = c_int::try_from(pass.len()).unwrap_or(0);
            if EVP_PBE_CipherInit((*a).algorithm.cast(), pass.as_ptr().cast(), plen, (*a).parameter.cast(), ctx, 0) != 0 {
                let mut out = vec![0u8; data.len() + 64];
                let mut n = 0;
                let dlen = c_int::try_from(data.len()).unwrap_or(0);
                if EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut n, data.as_ptr(), dlen) != 0 {
                    let at = usize::try_from(n).unwrap_or(0);
                    assert!(at <= out.len(), "decrypted past the buffer");
                    let mut m = 0;
                    EVP_CipherFinal_ex(ctx, out.as_mut_ptr().add(at), &mut m);
                }
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        X509_ALGOR_free(a);
        ERR_clear_error();
    }
});
