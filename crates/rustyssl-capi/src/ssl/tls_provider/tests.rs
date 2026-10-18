//! The EVP provider cross-checked against the core's own test provider (`rustyssl-crypto`
//! directly) and known answers. Each test generates keys or runs whole algorithms, too slow for
//! Miri, which checks the unsafe code elsewhere.

use super::*;

use rustyssl_tls::consts::group as gid;
use rustyssl_tls::keysched;
use rustyssl_tls::testprov::TestProvider;
use rustyssl_tls::testprov::keys::PrivateKey as TestKey;

use crate::evp::legacy_md::EVP_sha256;
use crate::x509::cert::{
    X509_getm_notAfter, X509_getm_notBefore, X509_gmtime_adj, X509_new, X509_set_pubkey,
    X509_set_version, X509_sign, i2d_X509,
};

fn evp() -> EvpProvider {
    // SAFETY: the default library context; no property query.
    unsafe { EvpProvider::new(ptr::null_mut(), ptr::null()) }
}

fn test() -> TestProvider {
    TestProvider::new(b"tls-provider")
}

const DATA: &[u8] = b"the quick brown fox jumps over the lazy dog, again and again";

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn hashes_agree_and_fork() {
    let (e, t) = (evp(), test());
    for alg in [
        HashAlg::Md5Sha1,
        HashAlg::Md5,
        HashAlg::Sha1,
        HashAlg::Sha224,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ] {
        let mut a = e.hash(alg).unwrap();
        let mut b = t.hash(alg).unwrap();
        a.update(DATA);
        b.update(DATA);
        assert_eq!(a.current(), b.current(), "{alg:?}");
        assert_eq!(a.current().len(), alg.len(), "{alg:?}");
        let mut f = a.fork();
        f.update(b"more");
        b.update(b"more");
        assert_eq!(f.current(), b.current(), "{alg:?} fork");
        // The original carries on unchanged by its fork.
        a.update(b"more");
        assert_eq!(a.current(), b.current(), "{alg:?} after fork");
    }
}

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn hmacs_agree_and_reset() {
    let (e, t) = (evp(), test());
    for alg in [
        HashAlg::Sha1,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ] {
        let mut a = e.hmac(alg, b"key").unwrap();
        let mut b = t.hmac(alg, b"key").unwrap();
        a.update(DATA);
        b.update(DATA);
        let first = a.finish();
        assert_eq!(first, b.finish(), "{alg:?}");
        a.update(DATA);
        assert_eq!(a.finish(), first, "{alg:?}: the state resets to the key");
    }
}

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn hkdf_matches_rfc_8448() {
    // RFC 8448, section 3: the early secret of a handshake without a PSK.
    let e = evp();
    let early = keysched::hkdf_extract(&e, HashAlg::Sha256, &[], &[0; 32]).unwrap();
    let expected = [
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c,
        0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70,
        0xf9, 0x2a,
    ];
    assert_eq!(early.bytes(), &expected);
}

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn aeads_agree_both_ways_and_reject_tampering() {
    let (e, t) = (evp(), test());
    for alg in [
        AeadAlg::Aes128Gcm,
        AeadAlg::Aes256Gcm,
        AeadAlg::ChaCha20Poly1305,
        AeadAlg::Aes128Ccm,
        AeadAlg::Aes128Ccm8,
        AeadAlg::Aes256Ccm,
    ] {
        let key = vec![7u8; alg.key_len()];
        let nonce = [9u8; 12];
        let mut ours = DATA.to_vec();
        e.aead(alg, &key)
            .unwrap()
            .seal(&nonce, b"aad", &mut ours)
            .unwrap();
        let mut theirs = DATA.to_vec();
        t.aead(alg, &key)
            .unwrap()
            .seal(&nonce, b"aad", &mut theirs)
            .unwrap();
        assert_eq!(ours, theirs, "{alg:?}");
        assert_eq!(ours.len(), DATA.len() + alg.tag_len(), "{alg:?}");
        let mut back = theirs.clone();
        e.aead(alg, &key)
            .unwrap()
            .open(&nonce, b"aad", &mut back)
            .unwrap();
        assert_eq!(back, DATA, "{alg:?}");
        let mut bad = theirs.clone();
        if let Some(b) = bad.first_mut() {
            *b ^= 1;
        }
        assert!(
            e.aead(alg, &key)
                .unwrap()
                .open(&nonce, b"aad", &mut bad)
                .is_err(),
            "{alg:?}"
        );
        let mut bad_aad = theirs.clone();
        assert!(
            e.aead(alg, &key)
                .unwrap()
                .open(&nonce, b"other", &mut bad_aad)
                .is_err(),
            "{alg:?}"
        );
        let mut empty = Vec::new();
        e.aead(alg, &key)
            .unwrap()
            .seal(&nonce, b"", &mut empty)
            .unwrap();
        let mut empty_t = Vec::new();
        t.aead(alg, &key)
            .unwrap()
            .seal(&nonce, b"", &mut empty_t)
            .unwrap();
        assert_eq!(empty, empty_t, "{alg:?} empty");
        // An empty record (with the record header as AAD) opens to nothing, and only with its
        // tag: CCM authenticates in the data update, which an empty record still needs
        // (tlsfuzzer's test-aesccm, "empty app data with _8 ciphers").
        let mut sealed = Vec::new();
        e.aead(alg, &key)
            .unwrap()
            .seal(&nonce, b"aad", &mut sealed)
            .unwrap();
        let mut opened = sealed.clone();
        e.aead(alg, &key)
            .unwrap()
            .open(&nonce, b"aad", &mut opened)
            .unwrap();
        assert!(opened.is_empty(), "{alg:?} empty open: {opened:?}");
        let mut forged = sealed.clone();
        if let Some(b) = forged.last_mut() {
            *b ^= 1;
        }
        assert!(
            e.aead(alg, &key)
                .unwrap()
                .open(&nonce, b"aad", &mut forged)
                .is_err(),
            "{alg:?} empty with a bad tag"
        );
        let mut short = vec![0u8; alg.tag_len() - 1];
        assert!(
            e.aead(alg, &key)
                .unwrap()
                .open(&nonce, b"", &mut short)
                .is_err(),
            "{alg:?} short"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn cbc_ciphers_agree() {
    let (e, t) = (evp(), test());
    for alg in [
        CipherAlg::Aes128Cbc,
        CipherAlg::Aes256Cbc,
        CipherAlg::Camellia128Cbc,
        CipherAlg::Camellia256Cbc,
        CipherAlg::DesEde3Cbc,
    ] {
        let key = vec![3u8; alg.key_len()];
        let iv = vec![5u8; alg.block_len()];
        let mut ours = vec![0x42u8; alg.block_len() * 4];
        e.cipher(alg, &key, true)
            .unwrap()
            .crypt(&iv, &mut ours)
            .unwrap();
        let mut theirs = vec![0x42u8; alg.block_len() * 4];
        t.cipher(alg, &key, true)
            .unwrap()
            .crypt(&iv, &mut theirs)
            .unwrap();
        assert_eq!(ours, theirs, "{alg:?}");
        let mut dec = e.cipher(alg, &key, false).unwrap();
        dec.crypt(&iv, &mut ours).unwrap();
        assert_eq!(ours, vec![0x42u8; alg.block_len() * 4], "{alg:?}");
        // The same context with a new IV (each record's).
        let mut again = theirs.clone();
        dec.crypt(&iv, &mut again).unwrap();
        assert_eq!(again, vec![0x42u8; alg.block_len() * 4], "{alg:?} again");
    }
    let mut data = b"plain".to_vec();
    e.cipher(CipherAlg::Null, &[], true)
        .unwrap()
        .crypt(&[], &mut data)
        .unwrap();
    assert_eq!(data, b"plain");
}

#[test]
#[cfg_attr(miri, ignore = "whole algorithms, too slow for Miri")]
fn the_constant_time_record_mac_agrees() {
    let (e, t) = (evp(), test());
    let header = [1u8; 13];
    let record = vec![0x5au8; 300];
    for alg in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha384] {
        for size in [0usize, 1, 55, 64, 200, 300] {
            let ours = e
                .tls_cbc_mac(alg, b"mac key", &header, &record, size)
                .unwrap();
            let theirs = t
                .tls_cbc_mac(alg, b"mac key", &header, &record, size)
                .unwrap();
            assert_eq!(ours, theirs, "{alg:?} {size}");
        }
    }
    assert!(
        e.tls_cbc_mac(HashAlg::Sha256, b"k", &header, &record, 301)
            .is_err()
    );
}

#[test]
#[cfg_attr(miri, ignore = "calls into the providers")]
fn groups_come_from_the_capabilities() {
    let e = evp();
    let g = e.groups();
    assert_eq!(g.first().map(|g| g.name.as_str()), Some("X25519MLKEM768"));
    let p256 = g.iter().find(|g| g.id == gid::SECP256R1).unwrap();
    assert_eq!(p256.name, "secp256r1");
    assert_eq!(p256.internal_name, "prime256v1");
    assert_eq!(p256.aliases, ["P-256"]);
    assert_eq!(
        (p256.min_tls, p256.max_tls),
        (rustyssl_abi::TLS1_VERSION, 0)
    );
    let kem = g.iter().find(|g| g.id == gid::MLKEM768).unwrap();
    assert!(kem.is_kem);
    assert_eq!(kem.security_bits, 192);
    // Every code point once.
    let mut ids: Vec<u16> = g.iter().map(|g| g.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), g.len());
    let s = e.sigalgs();
    assert_eq!(
        s.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["mldsa44", "mldsa65", "mldsa87"]
    );
}

/// The groups both providers offer.
const SHARED_GROUPS: [u16; 11] = [
    gid::X25519,
    gid::X448,
    gid::SECP256R1,
    gid::SECP384R1,
    gid::SECP521R1,
    gid::FFDHE2048,
    gid::MLKEM768,
    gid::MLKEM1024,
    gid::X25519_MLKEM768,
    gid::SECP256R1_MLKEM768,
    gid::SECP384R1_MLKEM1024,
];

#[test]
#[cfg_attr(miri, ignore = "key generation, too slow for Miri")]
fn key_shares_interoperate_both_ways() {
    let (e, t) = (evp(), test());
    for id in SHARED_GROUPS {
        // Our client, their server.
        let share = e.key_share(id).unwrap();
        let (answer, server_secret) = t.respond(id, share.public()).unwrap();
        let client_secret = share.derive(&answer).unwrap();
        assert_eq!(
            client_secret.bytes(),
            server_secret.bytes(),
            "{id:#x} ours to theirs"
        );
        // Their client, our server.
        let share = t.key_share(id).unwrap();
        let (answer, server_secret) = e.respond(id, share.public()).unwrap();
        let client_secret = share.derive(&answer).unwrap();
        assert_eq!(
            client_secret.bytes(),
            server_secret.bytes(),
            "{id:#x} theirs to ours"
        );
        assert!(!server_secret.is_empty());
    }
    assert!(e.key_share(0x7777).is_err());
    assert!(e.respond(gid::X25519, &[1, 2, 3]).is_err());
}

#[test]
#[cfg_attr(miri, ignore = "key generation, too slow for Miri")]
fn explicit_dh_shares_agree() {
    // RFC 7919's ffdhe2048 prime, as a TLS 1.2 server would send it.
    let g = rustyssl_crypto::ffc::by_name("ffdhe2048").unwrap();
    let p =
        g.p.to_bin(Some(256), rustyssl_crypto::bn::Endian::Big, false)
            .unwrap()
            .to_vec();
    let e = evp();
    let a = e.dh_share(&p, &[2]).unwrap();
    let b = e.dh_share(&p, &[2]).unwrap();
    assert_eq!(a.public().len(), p.len());
    let pa = a.public().to_vec();
    let sb = b.public().to_vec();
    let s1 = a.derive(&sb).unwrap();
    let s2 = b.derive(&pa).unwrap();
    assert_eq!(s1.bytes(), s2.bytes());
    assert_eq!(s1.len(), p.len());
}

/// A key of `alg` (with `group` for EC) generated through EVP.
fn evp_key(alg: &CStr, group: Option<&CStr>) -> Pkey {
    // SAFETY: the default library context; NUL-terminated names.
    let ctx =
        PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null()) });
    assert!(!ctx.0.is_null());
    // SAFETY: the context made above.
    assert!(unsafe { EVP_PKEY_keygen_init(ctx.0) } > 0);
    if let Some(g) = group {
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_CTX_set_group_name(ctx.0, g.as_ptr()) } > 0);
    }
    let mut k: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: as above; the slot.
    assert!(unsafe { EVP_PKEY_keygen(ctx.0, &raw mut k) } > 0);
    Pkey(k)
}

/// A self-signed certificate of `key`, DER.
fn cert_of(key: &Pkey, md: bool) -> Vec<u8> {
    // SAFETY: no preconditions.
    let x = X509Ptr(unsafe { X509_new() });
    // SAFETY: the certificate.
    assert!(unsafe { X509_set_version(x.0, 2) } != 0);
    // SAFETY: as above.
    let nb = unsafe { X509_getm_notBefore(x.0) };
    // SAFETY: the certificate's time.
    assert!(!unsafe { X509_gmtime_adj(nb, 0) }.is_null());
    // SAFETY: as above.
    let na = unsafe { X509_getm_notAfter(x.0) };
    // SAFETY: the certificate's time.
    assert!(!unsafe { X509_gmtime_adj(na, 3600) }.is_null());
    // SAFETY: the certificate; the key.
    assert!(unsafe { X509_set_pubkey(x.0, key.0) } != 0);
    let md_p = if md {
        // SAFETY: no preconditions.
        unsafe { EVP_sha256() }
    } else {
        ptr::null()
    };
    // SAFETY: the certificate; the key; the digest or NULL.
    assert!(unsafe { X509_sign(x.0, key.0, md_p) } > 0);
    let mut out: *mut u8 = ptr::null_mut();
    // SAFETY: as above; the slot for the encoding.
    let n = unsafe { i2d_X509(x.0, &raw mut out) };
    assert!(n > 0);
    // SAFETY: the `n` octets written.
    let der = unsafe { core::slice::from_raw_parts(out, usize::try_from(n).unwrap()) }.to_vec();
    // SAFETY: the encoding's buffer, freed once.
    unsafe { mem::release(out.cast()) };
    der
}

#[test]
#[cfg_attr(miri, ignore = "key generation, too slow for Miri")]
fn signatures_verify_both_ways() {
    let (e, t) = (evp(), test());
    use sigscheme as s;
    let rsa = evp_key(c"RSA", None);
    let ec = evp_key(c"EC", Some(c"P-256"));
    let ed = evp_key(c"ED25519", None);
    let cases: [(&Pkey, bool, &[u16]); 3] = [
        (
            &rsa,
            true,
            &[
                s::RSA_PSS_RSAE_SHA256,
                s::RSA_PSS_RSAE_SHA384,
                s::RSA_PKCS1_SHA256,
                s::RSA_PKCS1_SHA1,
                RSA_PKCS1_MD5_SHA1,
            ],
        ),
        (&ec, true, &[s::ECDSA_SECP256R1_SHA256, s::ECDSA_SHA1]),
        (&ed, false, &[s::ED25519]),
    ];
    for (key, md, schemes) in cases {
        let cert = cert_of(key, md);
        // SAFETY: a live key.
        let id = unsafe { e.add_key(key.0) }.unwrap();
        // SAFETY: as above: the same key gets the same id.
        assert_eq!(unsafe { e.add_key(key.0) }, Some(id));
        for &scheme in schemes {
            let sig = e
                .sign(id, scheme, DATA)
                .unwrap_or_else(|err| panic!("{scheme:#x}: {err}"));
            assert!(e.verify(&cert, scheme, DATA, &sig).unwrap(), "{scheme:#x}");
            assert!(
                !e.verify(&cert, scheme, b"other", &sig).unwrap(),
                "{scheme:#x}"
            );
            assert!(
                t.verify(&cert, scheme, DATA, &sig).unwrap(),
                "{scheme:#x} theirs"
            );
        }
    }
    // Their keys and certificates, our verification.
    let tk = TestKey::ec(rustyssl_abi::NID_X9_62_prime256v1, &t).unwrap();
    let cert = tk.public(&t).unwrap().cert("test");
    let id = t.add_key(tk);
    let sig = t.sign(id, s::ECDSA_SECP256R1_SHA256, DATA).unwrap();
    assert!(
        e.verify(&cert, s::ECDSA_SECP256R1_SHA256, DATA, &sig)
            .unwrap()
    );
    assert!(e.sign(KeyId(99), s::ED25519, DATA).is_err());
    assert!(
        e.verify(b"not a certificate", s::ED25519, DATA, &sig)
            .is_err()
    );
}

#[test]
#[cfg_attr(miri, ignore = "key generation, too slow for Miri")]
fn rsa_key_exchange_round_trips_with_implicit_rejection() {
    let e = evp();
    let rsa = evp_key(c"RSA", None);
    let cert = cert_of(&rsa, true);
    // SAFETY: a live key.
    let id = unsafe { e.add_key(rsa.0) }.unwrap();
    let mut pms = vec![0x03, 0x03];
    pms.extend_from_slice(&[0x11; 46]);
    let ct = e.rsa_encrypt(&cert, &pms).unwrap();
    assert_eq!(
        e.rsa_decrypt_pms(id, &ct, 0x0303).unwrap().bytes(),
        pms.as_slice()
    );
    // The wrong client version, or garbage, gives a random secret of the right length, never an
    // error the peer could see.
    let wrong = e.rsa_decrypt_pms(id, &ct, 0x0302).unwrap();
    assert_eq!(wrong.len(), 48);
    assert_ne!(wrong.bytes(), pms.as_slice());
    let mut bad = ct.clone();
    if let Some(b) = bad.last_mut() {
        *b ^= 1;
    }
    assert_eq!(e.rsa_decrypt_pms(id, &bad, 0x0303).unwrap().len(), 48);
}

#[test]
#[cfg_attr(miri, ignore = "calls into the random generator")]
fn random_octets_differ() {
    let e = evp();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    e.random(&mut a, false).unwrap();
    e.random(&mut b, true).unwrap();
    assert_ne!(a, b);
}
