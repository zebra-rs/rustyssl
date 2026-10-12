//! Fuzzes signing through digest contexts with the MAC signatures (`EVP_DigestSign*`): the
//! input picks a MAC key type and digest, a key, and data in pieces. A signature must equal the
//! MAC computed in one shot (`EVP_Q_mac`), whether the data comes in pieces or at once, signed
//! again after a final that leaves the context usable, or from a copy of the context. Nothing
//! may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Pkey = c_void;
type MdCtx = c_void;

unsafe extern "C" {
    fn EVP_PKEY_new_raw_private_key_ex(
        lib: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
        key: *const u8,
        len: usize,
    ) -> *mut Pkey;
    fn EVP_PKEY_new_CMAC_key(
        e: *mut c_void,
        key: *const u8,
        len: usize,
        cipher: *const c_void,
    ) -> *mut Pkey;
    fn EVP_get_cipherbyname(name: *const c_char) -> *const c_void;
    fn EVP_PKEY_free(k: *mut Pkey);
    fn EVP_MD_CTX_new() -> *mut MdCtx;
    fn EVP_MD_CTX_free(c: *mut MdCtx);
    fn EVP_MD_CTX_copy_ex(out: *mut MdCtx, inp: *const MdCtx) -> c_int;
    fn EVP_DigestSignInit_ex(
        ctx: *mut MdCtx,
        pctx: *mut *mut c_void,
        mdname: *const c_char,
        lib: *mut c_void,
        props: *const c_char,
        pkey: *mut Pkey,
        params: *const c_void,
    ) -> c_int;
    fn EVP_DigestSignUpdate(ctx: *mut MdCtx, data: *const c_void, len: usize) -> c_int;
    fn EVP_DigestSignFinal(ctx: *mut MdCtx, sig: *mut u8, len: *mut usize) -> c_int;
    fn EVP_DigestSign(
        ctx: *mut MdCtx,
        sig: *mut u8,
        len: *mut usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_Q_mac(
        lib: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
        subalg: *const c_char,
        params: *const c_void,
        key: *const c_void,
        keylen: usize,
        data: *const u8,
        datalen: usize,
        out: *mut u8,
        outsize: usize,
        outlen: *mut usize,
    ) -> *mut u8;
    fn ERR_clear_error();
}

const DIGESTS: [&CStr; 6] = [c"SHA256", c"SHA1", c"SHA2-512", c"SHA3-256", c"MD5", c"SM3"];
const CIPHERS: [&CStr; 3] = [c"AES-128-CBC", c"AES-256-CBC", c"DES-EDE3-CBC"];

/// Signs `pieces` with `pkey` and digest `md` (NULL for none): the signature, signed twice,
/// and from a copy; `None` if the init fails.
fn sign(pkey: *mut Pkey, md: *const c_char, pieces: &[&[u8]]) -> Option<Vec<u8>> {
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    // SAFETY: the context and key; the name.
    let ok = unsafe {
        EVP_DigestSignInit_ex(
            ctx,
            ptr::null_mut(),
            md,
            ptr::null_mut(),
            ptr::null(),
            pkey,
            ptr::null(),
        )
    };
    let mut result = None;
    if ok == 1 {
        for p in pieces {
            // SAFETY: the context; the piece.
            assert_eq!(
                unsafe { EVP_DigestSignUpdate(ctx, p.as_ptr().cast(), p.len()) },
                1
            );
        }
        let mut out = [0u8; 128];
        let mut len = out.len();
        // SAFETY: the context; the buffer.
        if unsafe { EVP_DigestSignFinal(ctx, out.as_mut_ptr(), &raw mut len) } == 1 {
            let first = out.get(..len).map(<[u8]>::to_vec);
            let mut len2 = out.len();
            // A first final leaves the context able to sign again.
            // SAFETY: as above.
            assert_eq!(
                unsafe { EVP_DigestSignFinal(ctx, out.as_mut_ptr(), &raw mut len2) },
                1
            );
            assert_eq!(out.get(..len2).map(<[u8]>::to_vec), first);
            // SAFETY: no preconditions.
            let copy = unsafe { EVP_MD_CTX_new() };
            // SAFETY: both contexts.
            assert_eq!(unsafe { EVP_MD_CTX_copy_ex(copy, ctx) }, 1);
            let mut len3 = out.len();
            // SAFETY: the copy; the buffer.
            assert_eq!(
                unsafe { EVP_DigestSignFinal(copy, out.as_mut_ptr(), &raw mut len3) },
                1
            );
            assert_eq!(out.get(..len3).map(<[u8]>::to_vec), first);
            // SAFETY: made above.
            unsafe { EVP_MD_CTX_free(copy) };
            result = first;
        }
    }
    // SAFETY: made above.
    unsafe { EVP_MD_CTX_free(ctx) };
    result
}

fuzz_target!(|data: &[u8]| {
    let [kind, choice, keylen, rest @ ..] = data else {
        return;
    };
    let keylen = usize::from(*keylen).min(rest.len()).min(64);
    let (key, msg) = rest.split_at(keylen);
    let digest = DIGESTS[usize::from(*choice) % DIGESTS.len()];
    let cipher = CIPHERS[usize::from(*choice) % CIPHERS.len()];
    let (pkey, mac, sub, md): (_, &CStr, *const c_char, *const c_char) = match kind % 4 {
        // SAFETY: a static name; the key's octets.
        0 => (
            unsafe {
                EVP_PKEY_new_raw_private_key_ex(
                    ptr::null_mut(),
                    c"HMAC".as_ptr(),
                    ptr::null(),
                    key.as_ptr(),
                    key.len(),
                )
            },
            c"HMAC",
            digest.as_ptr(),
            digest.as_ptr(),
        ),
        // SAFETY: as above.
        1 => (
            unsafe {
                EVP_PKEY_new_raw_private_key_ex(
                    ptr::null_mut(),
                    c"SIPHASH".as_ptr(),
                    ptr::null(),
                    key.as_ptr(),
                    key.len(),
                )
            },
            c"SIPHASH",
            ptr::null(),
            ptr::null(),
        ),
        // SAFETY: as above.
        2 => (
            unsafe {
                EVP_PKEY_new_raw_private_key_ex(
                    ptr::null_mut(),
                    c"POLY1305".as_ptr(),
                    ptr::null(),
                    key.as_ptr(),
                    key.len(),
                )
            },
            c"POLY1305",
            ptr::null(),
            ptr::null(),
        ),
        _ => {
            // SAFETY: a static name.
            let c = unsafe { EVP_get_cipherbyname(cipher.as_ptr()) };
            // SAFETY: the key's octets; the cipher.
            (
                unsafe { EVP_PKEY_new_CMAC_key(ptr::null_mut(), key.as_ptr(), key.len(), c) },
                c"CMAC",
                cipher.as_ptr(),
                ptr::null(),
            )
        }
    };
    if pkey.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        return;
    }
    // The data in pieces split at the input's own octets.
    let split = usize::from(*choice) % (msg.len() + 1);
    let (a, b) = msg.split_at(split);
    let pieced = sign(pkey, md, &[a, b]);
    let whole = sign(pkey, md, &[msg]);
    assert_eq!(pieced, whole);
    if let Some(sig) = &pieced {
        // The one-shot MAC agrees.
        let mut out = [0u8; 128];
        let mut outlen = 0usize;
        // SAFETY: static names; the key and data; the buffer.
        let r = unsafe {
            EVP_Q_mac(
                ptr::null_mut(),
                mac.as_ptr(),
                ptr::null(),
                sub,
                ptr::null(),
                key.as_ptr().cast(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                out.as_mut_ptr(),
                out.len(),
                &raw mut outlen,
            )
        };
        if !r.is_null() {
            assert_eq!(out.get(..outlen), Some(&sig[..]));
        }
        // And so does one-shot signing.
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        // SAFETY: the context and key.
        if unsafe {
            EVP_DigestSignInit_ex(
                ctx,
                ptr::null_mut(),
                md,
                ptr::null_mut(),
                ptr::null(),
                pkey,
                ptr::null(),
            )
        } == 1
        {
            let mut len = out.len();
            // SAFETY: the context; the buffer and data.
            if unsafe {
                EVP_DigestSign(ctx, out.as_mut_ptr(), &raw mut len, msg.as_ptr(), msg.len())
            } == 1
            {
                assert_eq!(out.get(..len), Some(&sig[..]));
            }
        }
        // SAFETY: made above.
        unsafe { EVP_MD_CTX_free(ctx) };
    }
    // SAFETY: made above.
    unsafe { EVP_PKEY_free(pkey) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
