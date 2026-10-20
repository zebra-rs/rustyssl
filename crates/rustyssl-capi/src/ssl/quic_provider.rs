//! QUIC's cryptography over EVP (ADR 0006): the transport's header protection, fetched from the
//! connection's library context as OpenSSL's `quic_record_util.c` does. AES masks are one ECB
//! block of the sample; ChaCha20's are the keystream for the sample as counter and nonce
//! (RFC 9001, 5.4.3 and 5.4.4). Everything else comes from the TLS core's [`EvpProvider`].

use core::ffi::c_int;
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{EVP_CIPHER, EVP_CIPHER_CTX};
use rustyssl_quic::crypto::{HeaderProtection, HpAlg, Provider as QuicProvider};
use rustyssl_tls::crypto::Secret;
use rustyssl_tls::error::{Error, Result};

use super::tls_provider::EvpProvider;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding, EVP_CipherInit_ex,
    EVP_CipherUpdate,
};

fn fail() -> Error {
    Error::internal()
}

/// An owned `EVP_CIPHER_CTX` with its fetched `EVP_CIPHER`.
struct Ctx {
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *mut EVP_CIPHER,
}

// SAFETY: the context and cipher are used by their single owner, under its mutex; OpenSSL's
// objects aren't tied to a thread.
unsafe impl Send for Ctx {}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: owned, or NULL; released once.
        unsafe { EVP_CIPHER_CTX_free(self.ctx) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(self.cipher) };
    }
}

/// Header protection with one EVP cipher.
struct EvpHp {
    ctx: Mutex<Ctx>,
    chacha: bool,
    /// ChaCha20's key (zeroized on drop), set again with each sample.
    key: Secret,
}

impl HeaderProtection for EvpHp {
    fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5]> {
        let c = self.ctx.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = [0u8; 16];
        let mut outl: c_int = 0;
        let ok = if self.chacha {
            // The sample is ChaCha20's 16-octet IV (counter, then nonce); the mask is the
            // keystream, the encryption of zeros.
            let zeros = [0u8; 5];
            // SAFETY: the context and cipher are live; the key has the cipher's length (checked
            // when made); the IV is 16 octets.
            (unsafe { EVP_CipherInit_ex(c.ctx, c.cipher, ptr::null_mut(), self.key.bytes().as_ptr(), sample.as_ptr(), 1) }) != 0
                // SAFETY: `out` has room for 16 octets, more than the 5 in.
                && unsafe { EVP_CipherUpdate(c.ctx, out.as_mut_ptr(), &raw mut outl, zeros.as_ptr(), 5) } != 0
                && outl == 5
        } else {
            // SAFETY: the context was initialised with the key; one 16-octet block in, one out.
            (unsafe {
                EVP_CipherUpdate(c.ctx, out.as_mut_ptr(), &raw mut outl, sample.as_ptr(), 16)
            }) != 0
                && outl == 16
        };
        if !ok {
            return Err(fail());
        }
        let [a, b, c2, d, e, ..] = out;
        Ok([a, b, c2, d, e])
    }
}

impl QuicProvider for EvpProvider {
    fn header_protection(&self, alg: HpAlg, key: &[u8]) -> Result<Box<dyn HeaderProtection>> {
        if key.len() != alg.key_len() {
            return Err(fail());
        }
        let name = match alg {
            HpAlg::Aes128 => c"AES-128-ECB",
            HpAlg::Aes256 => c"AES-256-ECB",
            HpAlg::ChaCha20 => c"ChaCha20",
        };
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let cipher = unsafe { EVP_CIPHER_fetch(self.libctx(), name.as_ptr(), self.propq()) };
        let ctx = Ctx {
            // SAFETY: no preconditions.
            ctx: unsafe { EVP_CIPHER_CTX_new() },
            cipher,
        };
        if ctx.ctx.is_null() || ctx.cipher.is_null() {
            return Err(fail());
        }
        let chacha = alg == HpAlg::ChaCha20;
        if !chacha {
            // SAFETY: the context and cipher; the key, of the cipher's length; ECB has no IV.
            let ok = unsafe { EVP_CipherInit_ex(ctx.ctx, ctx.cipher, ptr::null_mut(), key.as_ptr(), ptr::null(), 1) } != 0
                // SAFETY: the context.
                && unsafe { EVP_CIPHER_CTX_set_padding(ctx.ctx, 0) } != 0;
            if !ok {
                return Err(fail());
            }
        }
        Ok(Box::new(EvpHp {
            ctx: Mutex::new(ctx),
            chacha,
            key: Secret::new(key.to_vec()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> EvpProvider {
        // SAFETY: the default library context and no property query.
        unsafe { EvpProvider::new(ptr::null_mut(), ptr::null()) }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0))
            .collect()
    }

    /// RFC 9001, Appendix A.2 (client Initial, AES-128) and A.5 (ChaCha20) masks, the same as
    /// the transport's own provider computes.
    #[test]
    fn masks_match_rfc9001() {
        let p = provider();
        let hp = p
            .header_protection(HpAlg::Aes128, &hex("9f50449e04a0e810283a1e9933adedd2"))
            .unwrap();
        let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
        assert_eq!(hp.mask(&sample).unwrap().to_vec(), hex("437b9aec36"));
        // Twice: the context is reusable.
        assert_eq!(hp.mask(&sample).unwrap().to_vec(), hex("437b9aec36"));
        let hp = p
            .header_protection(
                HpAlg::ChaCha20,
                &hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            )
            .unwrap();
        let sample: [u8; 16] = hex("5e5cd55c41f69080575d7999c25a5bfb").try_into().unwrap();
        assert_eq!(hp.mask(&sample).unwrap().to_vec(), hex("aefefe7d03"));
        assert!(p.header_protection(HpAlg::Aes256, &[0; 16]).is_err());
    }

    /// A packet protected through EVP opens with the transport's test provider and back, and
    /// the RFC 9001 client Initial (A.2) is reproduced byte for byte.
    #[test]
    fn packet_protection_over_evp() {
        let p = provider();
        let dcid = hex("8394c8f03e515708");
        let (mut ckeys, _) = rustyssl_quic::packet::initial_keys(&p, &dcid).unwrap();
        let tp = rustyssl_quic::testprov::TestProvider::new(b"x");
        let (mut ckeys2, _) = rustyssl_quic::packet::initial_keys(&tp, &dcid).unwrap();
        let d = rustyssl_quic::wire::ConnId::new(&dcid).unwrap();
        let s = rustyssl_quic::wire::ConnId::default();
        let o = rustyssl_quic::packet::Outgoing {
            ty: rustyssl_quic::packet::PacketType::Initial,
            dcid: &d,
            scid: &s,
            token: &[],
            pn: 2,
            pn_len: 4,
            key_phase: false,
        };
        let payload = vec![0x01u8; 64];
        let mut a = Vec::new();
        let mut b = Vec::new();
        rustyssl_quic::packet::protect(&mut ckeys, &o, &payload, &mut a).unwrap();
        rustyssl_quic::packet::protect(&mut ckeys2, &o, &payload, &mut b).unwrap();
        assert_eq!(a, b);
        let (l, _) = rustyssl_quic::packet::locate(&a, 0).unwrap();
        let opened = rustyssl_quic::packet::unprotect(&mut ckeys, l.bytes, l.pn_offset, None)
            .unwrap()
            .unwrap();
        assert_eq!((opened.pn, opened.payload), (2, payload));
    }
}
