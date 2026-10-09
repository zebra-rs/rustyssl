//! Fuzzes base64 (`EVP_Encode*`/`EVP_Decode*`) through the C ABI, with output buffers of exactly
//! the room the man page promises (so a write past it is an ASan error): arbitrary octets
//! encoded in chunks must decode back to themselves, and arbitrary text decoded in chunks, or as
//! one block, must stay within its buffers.

#![no_main]

use core::ffi::{c_int, c_uchar, c_void};

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn EVP_ENCODE_CTX_new() -> *mut c_void;
    fn EVP_ENCODE_CTX_free(ctx: *mut c_void);
    fn EVP_EncodeInit(ctx: *mut c_void);
    fn EVP_EncodeUpdate(ctx: *mut c_void, out: *mut c_uchar, outl: *mut c_int, input: *const c_uchar, inl: c_int) -> c_int;
    fn EVP_EncodeFinal(ctx: *mut c_void, out: *mut c_uchar, outl: *mut c_int);
    fn EVP_DecodeInit(ctx: *mut c_void);
    fn EVP_DecodeUpdate(ctx: *mut c_void, out: *mut c_uchar, outl: *mut c_int, input: *const c_uchar, inl: c_int) -> c_int;
    fn EVP_DecodeFinal(ctx: *mut c_void, out: *mut c_uchar, outl: *mut c_int) -> c_int;
    fn EVP_DecodeBlock(t: *mut c_uchar, f: *const c_uchar, n: c_int) -> c_int;
}

/// Encodes `data` in chunks of `chunk`: the text.
fn encode(data: &[u8], chunk: usize) -> Vec<u8> {
    // SAFETY: no preconditions; the context is freed below.
    let ctx = unsafe { EVP_ENCODE_CTX_new() };
    // SAFETY: a new context.
    unsafe { EVP_EncodeInit(ctx) };
    let mut text = Vec::new();
    for piece in data.chunks(chunk) {
        // Room for every line the held octets and this piece make, and a NUL.
        let mut out = vec![0u8; (piece.len() + 48) / 48 * 65 + 1].into_boxed_slice();
        let mut outl = 0;
        // SAFETY: as above; `out` has the room.
        let r = unsafe { EVP_EncodeUpdate(ctx, out.as_mut_ptr(), &mut outl, piece.as_ptr(), c_int::try_from(piece.len()).unwrap()) };
        assert_eq!(r, 1);
        text.extend_from_slice(&out[..usize::try_from(outl).unwrap()]);
    }
    let mut out = vec![0u8; 66].into_boxed_slice();
    let mut outl = 0;
    // SAFETY: as above.
    unsafe { EVP_EncodeFinal(ctx, out.as_mut_ptr(), &mut outl) };
    text.extend_from_slice(&out[..usize::try_from(outl).unwrap()]);
    // SAFETY: made above.
    unsafe { EVP_ENCODE_CTX_free(ctx) };
    text
}

/// Decodes `text` in chunks of `chunk`: the octets, or `None` on an error.
fn decode(text: &[u8], chunk: usize) -> Option<Vec<u8>> {
    // SAFETY: no preconditions; the context is freed below.
    let ctx = unsafe { EVP_ENCODE_CTX_new() };
    // SAFETY: a new context.
    unsafe { EVP_DecodeInit(ctx) };
    let mut data = Vec::new();
    let mut ok = true;
    for piece in text.chunks(chunk) {
        // Room for the groups the held characters (at most 64) and this piece make.
        let mut out = vec![0u8; (piece.len() + 64) / 4 * 3].into_boxed_slice();
        let mut outl = 0;
        // SAFETY: as above; `out` has the room.
        let r = unsafe { EVP_DecodeUpdate(ctx, out.as_mut_ptr(), &mut outl, piece.as_ptr(), c_int::try_from(piece.len()).unwrap()) };
        data.extend_from_slice(&out[..usize::try_from(outl).unwrap()]);
        if r < 0 {
            ok = false;
            break;
        }
        if r == 0 {
            break;
        }
    }
    let mut out = vec![0u8; 48].into_boxed_slice();
    let mut outl = 0;
    // SAFETY: as above.
    let r = unsafe { EVP_DecodeFinal(ctx, out.as_mut_ptr(), &mut outl) };
    data.extend_from_slice(&out[..usize::try_from(outl).unwrap()]);
    // SAFETY: made above.
    unsafe { EVP_ENCODE_CTX_free(ctx) };
    (ok && r == 1).then_some(data)
}

fuzz_target!(|input: &[u8]| {
    let Some((&first, data)) = input.split_first() else {
        return;
    };
    let chunk = usize::from(first % 80) + 1;
    let text = encode(data, chunk);
    assert_eq!(decode(&text, chunk).as_deref(), Some(data), "what is encoded decodes back");
    let _ = decode(data, chunk);
    let copy = data.to_vec().into_boxed_slice();
    let mut out = vec![0u8; copy.len() / 4 * 3 + 1].into_boxed_slice();
    // SAFETY: `copy` holds its length; `out` has room for 3 octets a group.
    let n = unsafe { EVP_DecodeBlock(out.as_mut_ptr(), copy.as_ptr(), c_int::try_from(copy.len()).unwrap()) };
    assert!(n == -1 || usize::try_from(n).unwrap() <= copy.len() / 4 * 3);
});
