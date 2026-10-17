//! Fuzzes HPKE's receiver on untrusted input, as ECH's server gets it: the first octet picks a
//! suite (each KEM, KDF, and AEAD) and mode, the next two the encapsulated key's length; a
//! recipient key from fixed input key material decapsulates that key and opens the rest as a
//! ciphertext (and the input is also parsed as a suite string). Nothing may crash or read out
//! of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, OSSL_HPKE_CTX, OSSL_HPKE_SUITE};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OSSL_HPKE_keygen(suite: OSSL_HPKE_SUITE, pub_: *mut c_uchar, publen: *mut usize, priv_: *mut *mut EVP_PKEY, ikm: *const c_uchar, ikmlen: usize, libctx: *mut c_void, propq: *const c_char) -> c_int;
    fn OSSL_HPKE_CTX_new(mode: c_int, suite: OSSL_HPKE_SUITE, role: c_int, libctx: *mut c_void, propq: *const c_char) -> *mut OSSL_HPKE_CTX;
    fn OSSL_HPKE_CTX_free(ctx: *mut OSSL_HPKE_CTX);
    fn OSSL_HPKE_CTX_set1_psk(ctx: *mut OSSL_HPKE_CTX, pskid: *const c_char, psk: *const c_uchar, psklen: usize) -> c_int;
    fn OSSL_HPKE_CTX_set1_authpub(ctx: *mut OSSL_HPKE_CTX, pub_: *const c_uchar, publen: usize) -> c_int;
    fn OSSL_HPKE_decap(ctx: *mut OSSL_HPKE_CTX, enc: *const c_uchar, enclen: usize, recippriv: *mut EVP_PKEY, info: *const c_uchar, infolen: usize) -> c_int;
    fn OSSL_HPKE_open(ctx: *mut OSSL_HPKE_CTX, pt: *mut c_uchar, ptlen: *mut usize, aad: *const c_uchar, aadlen: usize, ct: *const c_uchar, ctlen: usize) -> c_int;
    fn OSSL_HPKE_export(ctx: *mut OSSL_HPKE_CTX, secret: *mut c_uchar, secretlen: usize, label: *const c_uchar, labellen: usize) -> c_int;
    fn OSSL_HPKE_str2suite(str_: *const c_char, suite: *mut OSSL_HPKE_SUITE) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn ERR_clear_error();
}

const KEMS: [u16; 5] = [0x10, 0x11, 0x12, 0x20, 0x21];
const KDFS: [u16; 3] = [1, 2, 3];
const AEADS: [u16; 4] = [1, 2, 3, 0xffff];
const IKM: [u8; 66] = [0x5a; 66];
const PSK: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let Some((len, rest)) = rest.split_first_chunk::<2>() else { return };
    let p = usize::from(pick);
    let suite = OSSL_HPKE_SUITE {
        kem_id: KEMS[p % 5],
        kdf_id: KDFS[(p / 5) % 3],
        aead_id: AEADS[(p / 15) % 4],
    };
    let mode = c_int::try_from((p / 60) % 4).unwrap_or(0);
    let enclen = usize::from(u16::from_be_bytes(*len)).min(rest.len());
    let (enc, ct) = rest.split_at(enclen);
    // SAFETY: the input and local buffers, read and written within their lengths; the keys and
    // contexts made here, freed.
    unsafe {
        let mut rpub = [0u8; 200];
        let mut rpublen = rpub.len();
        let mut rk = ptr::null_mut();
        if OSSL_HPKE_keygen(suite, rpub.as_mut_ptr(), &mut rpublen, &mut rk, IKM.as_ptr(), 66.min(match suite.kem_id { 0x12 => 66, 0x11 => 48, 0x21 => 56, _ => 32 }), ptr::null_mut(), ptr::null()) == 1 {
            let ctx = OSSL_HPKE_CTX_new(mode, suite, 1, ptr::null_mut(), ptr::null());
            if mode == 1 || mode == 3 {
                OSSL_HPKE_CTX_set1_psk(ctx, c"id".as_ptr(), PSK.as_ptr(), PSK.len());
            }
            if mode == 2 || mode == 3 {
                // The recipient's own key as the sender's, and the input's first octets as one.
                OSSL_HPKE_CTX_set1_authpub(ctx, rpub.as_ptr(), rpublen);
                OSSL_HPKE_CTX_set1_authpub(ctx, enc.as_ptr(), enc.len());
            }
            if OSSL_HPKE_decap(ctx, enc.as_ptr(), enc.len(), rk, c"info".as_ptr().cast(), 4) == 1 {
                let mut pt = vec![0u8; ct.len().max(1)];
                let mut ptlen = pt.len();
                OSSL_HPKE_open(ctx, pt.as_mut_ptr(), &mut ptlen, ct.as_ptr(), ct.len().min(8), ct.as_ptr(), ct.len());
                let mut secret = [0u8; 64];
                OSSL_HPKE_export(ctx, secret.as_mut_ptr(), secret.len(), ct.as_ptr(), ct.len().min(66));
            }
            OSSL_HPKE_CTX_free(ctx);
            EVP_PKEY_free(rk);
        }
        let mut s = data.to_vec();
        s.retain(|&c| c != 0);
        s.push(0);
        let mut out = OSSL_HPKE_SUITE { kem_id: 0, kdf_id: 0, aead_id: 0 };
        OSSL_HPKE_str2suite(s.as_ptr().cast(), &mut out);
        ERR_clear_error();
    }
});
