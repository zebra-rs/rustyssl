//! A [`Provider`] over `rustyssl-crypto` directly, for the core's own tests (ADR 0002): the
//! state machines, the record layer, and the key schedules run against it with no C in the
//! loop. `rustyssl-capi`'s provider goes through EVP instead.
//!
//! Randomness is a deterministic stream (SHA-256 in counter mode over a seed), so a test can
//! replay a trace; [`TestProvider::queue_random`] makes the next draws given octets, as RFC 8448's
//! replay needs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test infrastructure"
)]

use std::cell::RefCell;
use std::collections::VecDeque;

use rustyssl_crypto::lowlevel::aead::{Ccm, Gcm};
use rustyssl_crypto::lowlevel::modes::{BLOCK, Block128};
use rustyssl_crypto::{ecx, mac, md, sym};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aead, AeadAlg, Cipher, CipherAlg, GroupInfo, Hash, HashAlg, KeyId, KeyShare, Mac, Provider,
    Secret, SigalgInfo,
};
use crate::error::{Error, Result};

pub mod keys;
pub mod keys_rsa;

/// The provider failed (a test bug or a refusal the test expects).
fn fail() -> Error {
    Error::internal()
}

/// The digest of a hash role.
pub fn md_alg(alg: HashAlg) -> md::Algorithm {
    match alg {
        HashAlg::Md5Sha1 => md::Algorithm::Md5Sha1,
        HashAlg::Md5 => md::Algorithm::Md5,
        HashAlg::Sha1 => md::Algorithm::Sha1,
        HashAlg::Sha224 => md::Algorithm::Sha224,
        HashAlg::Sha256 => md::Algorithm::Sha256,
        HashAlg::Sha384 => md::Algorithm::Sha384,
        HashAlg::Sha512 => md::Algorithm::Sha512,
        HashAlg::Sm3 => md::Algorithm::Sm3,
    }
}

/// A one-shot digest.
pub fn digest(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    let mut c = md::context(md_alg(alg));
    c.update(data).unwrap();
    let mut out = vec![0; alg.len()];
    c.finalize(&mut out).unwrap();
    out
}

struct TestHash {
    alg: HashAlg,
    ctx: Box<dyn md::Context>,
}

impl Hash for TestHash {
    fn update(&mut self, data: &[u8]) {
        self.ctx.update(data).unwrap();
    }

    fn current(&self) -> Vec<u8> {
        let mut c = self.ctx.clone_box();
        let mut out = vec![0; self.alg.len()];
        c.finalize(&mut out).unwrap();
        out
    }

    fn fork(&self) -> Box<dyn Hash> {
        Box::new(Self {
            alg: self.alg,
            ctx: self.ctx.clone_box(),
        })
    }
}

struct TestMac(Box<dyn mac::Mac>);

impl Mac for TestMac {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).unwrap();
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut out = vec![0; self.0.size()];
        self.0.finalize(&mut out).unwrap();
        self.0.reset();
        out
    }
}

/// A block cipher as the lowlevel modes take it (always encrypting: GCM and CCM only need that).
struct Enc<'a>(&'a dyn sym::BlockCipher);

impl Block128 for Enc<'_> {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = *input;
        self.0.encrypt_blocks(&mut b).unwrap();
        b
    }
}

enum AeadKind {
    Gcm(Box<dyn sym::BlockCipher>),
    Ccm(Box<dyn sym::BlockCipher>, usize),
    ChaCha(Vec<u8>),
}

struct TestAead(AeadKind);

/// RFC 8439's Poly1305 over `aad` and the ciphertext `ct` with the one-time key from `key` and
/// `nonce`.
fn chacha_tag(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[4..].copy_from_slice(nonce);
    let mut ks = sym::chacha20(key, &iv).unwrap();
    let mut otk = [0u8; 64];
    ks.apply(&mut otk);
    let mut p = mac::poly1305(&otk[..32]).unwrap();
    let pad = |p: &mut Box<dyn mac::Mac>, n: usize| {
        let rem = n % 16;
        if rem != 0 {
            p.update(&[0u8; 16][..16 - rem]).unwrap();
        }
    };
    p.update(aad).unwrap();
    pad(&mut p, aad.len());
    p.update(ct).unwrap();
    pad(&mut p, ct.len());
    p.update(&(aad.len() as u64).to_le_bytes()).unwrap();
    p.update(&(ct.len() as u64).to_le_bytes()).unwrap();
    let mut tag = [0u8; 16];
    p.finalize(&mut tag).unwrap();
    tag
}

/// ChaCha20 from block 1, as RFC 8439 encrypts.
fn chacha_crypt(key: &[u8], nonce: &[u8], data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[0] = 1;
    iv[4..].copy_from_slice(nonce);
    sym::chacha20(key, &iv).unwrap().apply(data);
}

impl Aead for TestAead {
    fn seal(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
        match &self.0 {
            AeadKind::Gcm(b) => {
                let e = Enc(b.as_ref());
                let mut g = Gcm::new(&e);
                g.setiv(nonce, &e);
                if g.aad(aad) != 0 {
                    return Err(fail());
                }
                let input = data.clone();
                if g.encrypt(&input, data, &e) != 0 {
                    return Err(fail());
                }
                let mut tag = [0u8; 16];
                g.tag(&mut tag);
                data.extend_from_slice(&tag);
            }
            AeadKind::Ccm(b, tag_len) => {
                let e = Enc(b.as_ref());
                let mut c = Ccm {
                    nonce: [0; BLOCK],
                    cmac: [0; BLOCK],
                    blocks: 0,
                };
                c.init(
                    u32::try_from(*tag_len).unwrap(),
                    u32::try_from(15 - nonce.len()).unwrap(),
                );
                if c.setiv(nonce, data.len()) != 0 {
                    return Err(fail());
                }
                c.aad(aad, &e);
                let input = data.clone();
                if c.encrypt(&input, data, &e) != 0 {
                    return Err(fail());
                }
                let mut tag = vec![0u8; *tag_len];
                c.tag(&mut tag, *tag_len);
                data.extend_from_slice(&tag);
            }
            AeadKind::ChaCha(key) => {
                chacha_crypt(key, nonce, data);
                let tag = chacha_tag(key, nonce, aad, data);
                data.extend_from_slice(&tag);
            }
        }
        Ok(())
    }

    fn open(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
        let bad = || {
            Error::alert(
                rustyssl_abi::SSL_AD_BAD_RECORD_MAC,
                rustyssl_abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC,
            )
        };
        let tag_len = match &self.0 {
            AeadKind::Ccm(_, t) => *t,
            _ => 16,
        };
        let Some(ct_len) = data.len().checked_sub(tag_len) else {
            return Err(bad());
        };
        let tag = data.split_off(ct_len);
        let ok = match &self.0 {
            AeadKind::Gcm(b) => {
                let e = Enc(b.as_ref());
                let mut g = Gcm::new(&e);
                g.setiv(nonce, &e);
                if g.aad(aad) != 0 {
                    return Err(bad());
                }
                let input = data.clone();
                if g.decrypt(&input, data, &e) != 0 {
                    return Err(bad());
                }
                g.finish(Some(&tag)) == 0
            }
            AeadKind::Ccm(b, t) => {
                let e = Enc(b.as_ref());
                let mut c = Ccm {
                    nonce: [0; BLOCK],
                    cmac: [0; BLOCK],
                    blocks: 0,
                };
                c.init(
                    u32::try_from(*t).unwrap(),
                    u32::try_from(15 - nonce.len()).unwrap(),
                );
                if c.setiv(nonce, data.len()) != 0 {
                    return Err(bad());
                }
                c.aad(aad, &e);
                let input = data.clone();
                if c.decrypt(&input, data, &e) != 0 {
                    return Err(bad());
                }
                let mut want = vec![0u8; *t];
                c.tag(&mut want, *t);
                bool::from(want.ct_eq(&tag))
            }
            AeadKind::ChaCha(key) => {
                let want = chacha_tag(key, nonce, aad, data);
                let ok = bool::from(want.ct_eq(&tag[..]));
                chacha_crypt(key, nonce, data);
                ok
            }
        };
        if ok {
            Ok(())
        } else {
            data.iter_mut().for_each(|b| *b = 0);
            Err(bad())
        }
    }
}

/// A CBC cipher (or the NULL cipher) in one direction.
struct TestCipher {
    block: Option<Box<dyn sym::BlockCipher>>,
    encrypt: bool,
}

impl Cipher for TestCipher {
    fn crypt(&mut self, iv: &[u8], data: &mut [u8]) -> Result<()> {
        let Some(b) = &self.block else { return Ok(()) };
        let n = b.block_size();
        if iv.len() != n || !data.len().is_multiple_of(n) {
            return Err(fail());
        }
        let mut prev = iv.to_vec();
        for chunk in data.chunks_mut(n) {
            if self.encrypt {
                chunk.iter_mut().zip(&prev).for_each(|(c, p)| *c ^= p);
                b.encrypt_blocks(chunk).map_err(|_| fail())?;
                prev.copy_from_slice(chunk);
            } else {
                let saved = chunk.to_vec();
                b.decrypt_blocks(chunk).map_err(|_| fail())?;
                chunk.iter_mut().zip(&prev).for_each(|(c, p)| *c ^= p);
                prev = saved;
            }
        }
        Ok(())
    }
}

/// SEED, which the crypto crate offers only as a low-level cipher.
#[derive(Clone)]
struct SeedBlock(rustyssl_crypto::lowlevel::seed::SeedKey);

impl sym::BlockCipher for SeedBlock {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> core::result::Result<(), sym::Error> {
        for b in data.chunks_mut(16) {
            let block: &[u8; 16] = (&*b).try_into().map_err(|_| sym::Error::BlockLength)?;
            let out = self.0.encrypt(block);
            b.copy_from_slice(&out);
        }
        Ok(())
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> core::result::Result<(), sym::Error> {
        for b in data.chunks_mut(16) {
            let block: &[u8; 16] = (&*b).try_into().map_err(|_| sym::Error::BlockLength)?;
            let out = self.0.decrypt(block);
            b.copy_from_slice(&out);
        }
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn sym::BlockCipher> {
        Box::new(self.clone())
    }
}

/// The block cipher of a CBC suite.
fn block_of(alg: CipherAlg, key: &[u8]) -> Result<Option<Box<dyn sym::BlockCipher>>> {
    use sym::BlockAlgorithm as B;
    let algorithm = match alg {
        CipherAlg::Null => return Ok(None),
        CipherAlg::Aes128Cbc | CipherAlg::Aes256Cbc => B::Aes,
        CipherAlg::Camellia128Cbc | CipherAlg::Camellia256Cbc => B::Camellia,
        CipherAlg::Aria128Cbc | CipherAlg::Aria256Cbc => B::Aria,
        CipherAlg::DesEde3Cbc => B::TripleDes,
        CipherAlg::SeedCbc => {
            let k: &[u8; 16] = key.try_into().map_err(|_| fail())?;
            return Ok(Some(Box::new(SeedBlock(
                rustyssl_crypto::lowlevel::seed::set_key(k),
            ))));
        }
        CipherAlg::Sm4Cbc => B::Sm4,
    };
    if key.len() != alg.key_len() {
        return Err(fail());
    }
    sym::block_cipher(algorithm, key, None)
        .map(Some)
        .map_err(|_| fail())
}

/// A test key share: for a Diffie-Hellman group, our private value and public share; for a
/// KEM, the decapsulation key.
pub struct TestShare {
    pub id: u16,
    pub public: Vec<u8>,
    pub private: keys::SharePrivate,
}

impl KeyShare for TestShare {
    fn public(&self) -> &[u8] {
        &self.public
    }

    fn derive(self: Box<Self>, peer: &[u8]) -> Result<Secret> {
        keys::derive(self.id, &self.private, peer)
    }
}

/// The test provider.
pub struct TestProvider {
    seed: Vec<u8>,
    counter: RefCell<u64>,
    /// Octets a test queued, drawn before the stream's.
    queued: RefCell<VecDeque<u8>>,
    /// The stream's octets not yet drawn.
    stream: RefCell<VecDeque<u8>>,
    /// The private keys a test registered; a [`KeyId`] is an index.
    pub keys: RefCell<Vec<keys::PrivateKey>>,
}

impl TestProvider {
    /// A provider whose randomness is the stream for `seed`.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: RefCell::new(0),
            queued: RefCell::new(VecDeque::new()),
            stream: RefCell::new(VecDeque::new()),
            keys: RefCell::new(Vec::new()),
        }
    }

    /// Makes the next random draws return `bytes` first.
    pub fn queue_random(&self, bytes: &[u8]) {
        self.queued.borrow_mut().extend(bytes);
    }

    /// Registers a private key, returning its handle.
    pub fn add_key(&self, key: keys::PrivateKey) -> KeyId {
        let mut k = self.keys.borrow_mut();
        k.push(key);
        KeyId(k.len() - 1)
    }

    /// The next `n` random octets.
    pub fn draw(&self, out: &mut [u8]) {
        let mut queued = self.queued.borrow_mut();
        let mut q = self.stream.borrow_mut();
        let mut i = 0;
        while i < out.len() {
            if let Some(b) = queued.pop_front().or_else(|| q.pop_front()) {
                out[i] = b;
                i += 1;
                continue;
            }
            let mut c = self.counter.borrow_mut();
            let mut input = self.seed.clone();
            input.extend_from_slice(&c.to_be_bytes());
            *c += 1;
            for b in digest(HashAlg::Sha256, &input) {
                q.push_back(b);
            }
        }
    }
}

impl Provider for TestProvider {
    fn hash(&self, alg: HashAlg) -> Result<Box<dyn Hash>> {
        Ok(Box::new(TestHash {
            alg,
            ctx: md::context(md_alg(alg)),
        }))
    }

    fn hmac(&self, alg: HashAlg, key: &[u8]) -> Result<Box<dyn Mac>> {
        Ok(Box::new(TestMac(
            mac::hmac(md_alg(alg), key).map_err(|_| fail())?,
        )))
    }

    fn aead(&self, alg: AeadAlg, key: &[u8]) -> Result<Box<dyn Aead>> {
        use sym::BlockAlgorithm as B;
        if key.len() != alg.key_len() {
            return Err(fail());
        }
        let block = |a| sym::block_cipher(a, key, None).map_err(|_| fail());
        let kind = match alg {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => AeadKind::Gcm(block(B::Aes)?),
            AeadAlg::Aria128Gcm | AeadAlg::Aria256Gcm => AeadKind::Gcm(block(B::Aria)?),
            AeadAlg::Sm4Gcm => AeadKind::Gcm(block(B::Sm4)?),
            AeadAlg::Aes128Ccm | AeadAlg::Aes256Ccm => AeadKind::Ccm(block(B::Aes)?, 16),
            AeadAlg::Aes128Ccm8 | AeadAlg::Aes256Ccm8 => AeadKind::Ccm(block(B::Aes)?, 8),
            AeadAlg::Sm4Ccm => AeadKind::Ccm(block(B::Sm4)?, 16),
            AeadAlg::ChaCha20Poly1305 => AeadKind::ChaCha(key.to_vec()),
        };
        Ok(Box::new(TestAead(kind)))
    }

    fn cipher(&self, alg: CipherAlg, key: &[u8], encrypt: bool) -> Result<Box<dyn Cipher>> {
        Ok(Box::new(TestCipher {
            block: block_of(alg, key)?,
            encrypt,
        }))
    }

    fn tls_cbc_mac(
        &self,
        alg: HashAlg,
        key: &[u8],
        header: &[u8; 13],
        data: &[u8],
        data_size: usize,
    ) -> Result<Vec<u8>> {
        use rustyssl_crypto::provided::mac::{RecordDigest, tls_cbc_record_mac};
        let d = match alg {
            HashAlg::Md5 => RecordDigest::Md5,
            HashAlg::Sha1 => RecordDigest::Sha1,
            HashAlg::Sha224 => RecordDigest::Sha224,
            HashAlg::Sha256 => RecordDigest::Sha256,
            HashAlg::Sha384 => RecordDigest::Sha384,
            HashAlg::Sha512 => RecordDigest::Sha512,
            _ => return Err(fail()),
        };
        Ok(tls_cbc_record_mac(d, header, data, data_size, key)
            .ok_or_else(fail)?
            .to_vec())
    }

    fn groups(&self) -> Vec<GroupInfo> {
        keys::groups()
    }

    fn sigalgs(&self) -> Vec<SigalgInfo> {
        Vec::new()
    }

    fn key_share(&self, id: u16) -> Result<Box<dyn KeyShare>> {
        let (public, private) = keys::generate(id, self)?;
        Ok(Box::new(TestShare {
            id,
            public,
            private,
        }))
    }

    fn dh_share(&self, p: &[u8], g: &[u8]) -> Result<Box<dyn KeyShare>> {
        use rustyssl_crypto::bn::{BigNum, Endian};
        let p = BigNum::from_bin(p, Endian::Big, false).map_err(|_| fail())?;
        let g = BigNum::from_bin(g, Endian::Big, false).map_err(|_| fail())?;
        let (public, private) = keys::dh_generate(&p, &g, self)?;
        Ok(Box::new(TestShare {
            id: 0,
            public,
            private,
        }))
    }

    fn respond(&self, id: u16, peer: &[u8]) -> Result<(Vec<u8>, Secret)> {
        keys::respond(id, peer, self)
    }

    fn random(&self, out: &mut [u8], _private: bool) -> Result<()> {
        self.draw(out);
        Ok(())
    }

    fn sign(&self, key: KeyId, scheme: u16, msg: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.borrow();
        let k = keys.get(key.0).ok_or_else(fail)?;
        keys::sign(k, scheme, msg, self)
    }

    fn verify(&self, cert: &[u8], scheme: u16, msg: &[u8], sig: &[u8]) -> Result<bool> {
        let public =
            keys::PublicKey::from_cert(cert).or_else(|_| keys::PublicKey::from_spki_der(cert))?;
        keys::verify(&public, scheme, msg, sig)
    }

    fn rsa_encrypt(&self, cert: &[u8], pms: &[u8]) -> Result<Vec<u8>> {
        let public = keys::PublicKey::from_cert(cert)?;
        keys::rsa_encrypt(&public, pms, self)
    }

    fn rsa_decrypt_pms(
        &self,
        key: KeyId,
        ciphertext: &[u8],
        client_version: u16,
    ) -> Result<Secret> {
        let keys = self.keys.borrow();
        let k = keys.get(key.0).ok_or_else(fail)?;
        keys::rsa_decrypt_pms(k, ciphertext, client_version, self)
    }

    fn peer_key(&self, der: &[u8], spki: bool) -> Result<crate::crypto::PeerKey> {
        let k = if spki {
            keys::PublicKey::from_spki_der(der)?
        } else {
            keys::PublicKey::from_cert(der)?
        };
        Ok(k.info())
    }
}

/// X25519, as the simplest share every test can use.
pub fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    ecx::x25519_public_from_private(private)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn chacha20_poly1305_matches_rfc_8439() {
        // RFC 8439, section 2.8.2.
        let p = TestProvider::new(b"kat");
        let key: Vec<u8> = (0x80u8..=0x9f).collect();
        let mut a = p.aead(AeadAlg::ChaCha20Poly1305, &key).unwrap();
        let nonce = h("070000004041424344454647");
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = pt.to_vec();
        a.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(&data[..16], &h("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(
            &data[data.len() - 16..],
            &h("1ae10b594f09e26a7e902ecbd0600691")[..]
        );
        a.open(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data, pt);
    }

    #[test]
    fn ccm_matches_rfc_3610() {
        // RFC 3610, packet vector #1: an 8-octet tag and a 13-octet nonce.
        let p = TestProvider::new(b"kat");
        let mut a = p
            .aead(AeadAlg::Aes128Ccm8, &h("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"))
            .unwrap();
        let nonce = h("00000003020100a0a1a2a3a4a5");
        let aad = h("0001020304050607");
        let mut data = h("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        a.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(
            data,
            h("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
        );
        a.open(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data, h("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e"));
    }

    #[test]
    fn aes_cbc_matches_sp800_38a() {
        // SP 800-38A, F.2.1 and F.2.2 (the first two blocks).
        let p = TestProvider::new(b"kat");
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = h("000102030405060708090a0b0c0d0e0f");
        let mut data = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        p.cipher(CipherAlg::Aes128Cbc, &key, true)
            .unwrap()
            .crypt(&iv, &mut data)
            .unwrap();
        assert_eq!(
            data,
            h("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
        );
        p.cipher(CipherAlg::Aes128Cbc, &key, false)
            .unwrap()
            .crypt(&iv, &mut data)
            .unwrap();
        assert_eq!(
            data,
            h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        );
    }

    #[test]
    fn random_is_deterministic_and_queueable() {
        let a = TestProvider::new(b"seed");
        let b = TestProvider::new(b"seed");
        let (mut x, mut y) = ([0u8; 50], [0u8; 50]);
        a.draw(&mut x);
        b.draw(&mut y);
        assert_eq!(x, y);
        a.queue_random(&[1, 2, 3]);
        let mut z = [0u8; 4];
        a.draw(&mut z);
        assert_eq!(&z[..3], &[1, 2, 3]);
    }

    #[test]
    fn x25519_matches_rfc_7748() {
        // RFC 7748, section 6.1.
        let k: [u8; 32] = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
        assert_eq!(
            x25519_public(&k).to_vec(),
            h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }
}
