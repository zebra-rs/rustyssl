#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test arithmetic on small known values"
)]

use super::super::aes::{Schedule, decrypt_schedule, encrypt_schedule};
use super::*;

struct Enc(Schedule);
struct Dec(Schedule);

impl Block128 for Enc {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.encrypt(input)
    }
}

impl Block128 for Dec {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.decrypt(input)
    }
}

/// A CTR function counting in the last 32 bits.
struct Ctr<'a>(&'a Enc);

impl Ctr128 for Ctr<'_> {
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; BLOCK]) {
        let mut c = *iv;
        for i in 0..blocks {
            let k = self.0.block(&c);
            for n in 0..BLOCK {
                out[i * BLOCK + n] = input[i * BLOCK + n] ^ k[n];
            }
            let v = u32::from_be_bytes(c[12..].try_into().unwrap()).wrapping_add(1);
            c[12..].copy_from_slice(&v.to_be_bytes());
        }
    }
}

/// A CCM function over the block function: CTR with the 64-bit counter, the plaintext into
/// the CBC-MAC.
struct CcmFn<'a>(&'a Enc, bool);

impl Ccm128 for CcmFn<'_> {
    fn ccm(
        &self,
        input: &[u8],
        out: &mut [u8],
        blocks: usize,
        ivec: &[u8; BLOCK],
        cmac: &mut [u8; BLOCK],
    ) {
        let mut c = *ivec;
        for i in 0..blocks {
            let k = self.0.block(&c);
            let x: [u8; BLOCK] = input[i * BLOCK..][..BLOCK].try_into().unwrap();
            let y: [u8; BLOCK] = core::array::from_fn(|n| x[n] ^ k[n]);
            out[i * BLOCK..][..BLOCK].copy_from_slice(&y);
            let p = if self.1 { x } else { y };
            for n in 0..BLOCK {
                cmac[n] ^= p[n];
            }
            *cmac = self.0.block(cmac);
            let v = u64::from_be_bytes(c[8..].try_into().unwrap()).wrapping_add(1);
            c[8..].copy_from_slice(&v.to_be_bytes());
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn aes(key: &str) -> (Enc, Dec) {
    let k = unhex(key);
    (
        Enc(encrypt_schedule(&k).unwrap()),
        Dec(decrypt_schedule(&k).unwrap()),
    )
}

/// McGrew and Viega's GCM test cases 2, 4, and 6, at once and in pieces, through the block
/// function and the CTR function.
#[test]
fn gcm_known_answers() {
    let cases = [
        (
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        (
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ),
        (
            "feffe9928665731c6d6a8f9467308308",
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
            "619cc5aefffe0bfa462af43c1699d050",
        ),
    ];
    for (key, iv, aad, p, c, t) in cases {
        let (e, _) = aes(key);
        let (iv, aad, p) = (unhex(iv), unhex(aad), unhex(p));
        for piece in [1usize, 5, 16, 17, 100] {
            for use_ctr in [false, true] {
                let mut g = Gcm::new(&e);
                g.setiv(&iv, &e);
                for a in aad.chunks(piece) {
                    assert_eq!(g.aad(a), 0);
                }
                let mut out = vec![0; p.len()];
                let mut at = 0;
                for chunk in p.chunks(piece) {
                    let o = &mut out[at..at + chunk.len()];
                    let r = if use_ctr {
                        g.encrypt_ctr32(chunk, o, &e, &Ctr(&e))
                    } else {
                        g.encrypt(chunk, o, &e)
                    };
                    assert_eq!(r, 0);
                    at += chunk.len();
                }
                assert_eq!(hex(&out), c, "{piece} {use_ctr}");
                assert_eq!(g.finish(Some(&unhex(t))), 0);

                let mut g = Gcm::new(&e);
                g.setiv(&iv, &e);
                g.aad(&aad);
                let mut back = vec![0; p.len()];
                let mut at = 0;
                for chunk in out.chunks(piece) {
                    let o = &mut back[at..at + chunk.len()];
                    let r = if use_ctr {
                        g.decrypt_ctr32(chunk, o, &e, &Ctr(&e))
                    } else {
                        g.decrypt(chunk, o, &e)
                    };
                    assert_eq!(r, 0);
                    at += chunk.len();
                }
                assert_eq!(back, p);
                let mut tag = [0u8; 16];
                g.tag(&mut tag);
                assert_eq!(hex(&tag), t);
            }
        }
    }
}

/// AAD after the message, the length limits, and the tag lengths.
#[test]
fn gcm_states() {
    let (e, _) = aes("feffe9928665731c6d6a8f9467308308");
    let mut g = Gcm::new(&e);
    g.setiv(&[1; 12], &e);
    let mut out = [0u8; 4];
    assert_eq!(g.encrypt(&[1, 2, 3, 4], &mut out, &e), 0);
    assert_eq!(g.aad(&[1]), -2);
    assert_eq!(g.finish(None), -1);
    assert_eq!(g.finish(Some(&[0; 17])), -1);
    // A tag of no octets always matches, as in OpenSSL.
    assert_eq!(g.finish(Some(&[])), 0);
    g.setiv(&[1; 12], &e);
    g.mlen = GCM_MAX_MESSAGE;
    assert_eq!(g.encrypt(&[1], &mut out, &e), -1);
    g.setiv(&[1; 12], &e);
    g.alen = GCM_MAX_AAD;
    assert_eq!(g.aad(&[1]), -1);
}

/// RFC 3610 packet vector 1, through the block function and the CCM function; a length
/// mismatch; the tag length.
#[test]
fn ccm_known_answer() {
    let (e, _) = aes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let nonce = unhex("00000003020100a0a1a2a3a4a5");
    let aad = unhex("0001020304050607");
    let p = unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    for stream in [false, true] {
        let mut c = Ccm {
            nonce: [0; 16],
            cmac: [0; 16],
            blocks: 0,
        };
        c.init(8, 2);
        assert_eq!(c.setiv(&nonce, p.len()), 0);
        c.aad(&aad, &e);
        let mut out = vec![0; p.len()];
        let r = if stream {
            c.encrypt_ccm64(&p, &mut out, &e, &CcmFn(&e, true))
        } else {
            c.encrypt(&p, &mut out, &e)
        };
        assert_eq!(r, 0);
        assert_eq!(hex(&out), "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
        let mut tag = [0u8; 8];
        assert_eq!(c.tag(&mut tag, 8), 8);
        assert_eq!(hex(&tag), "17e8d12cfdf926e0");
        assert_eq!(c.tag(&mut tag, 16), 0);

        let mut d = Ccm {
            nonce: [0; 16],
            cmac: [0; 16],
            blocks: 0,
        };
        d.init(8, 2);
        d.setiv(&nonce, p.len());
        d.aad(&aad, &e);
        let mut back = vec![0; p.len()];
        let r = if stream {
            d.decrypt_ccm64(&out, &mut back, &e, &CcmFn(&e, false))
        } else {
            d.decrypt(&out, &mut back, &e)
        };
        assert_eq!(r, 0);
        assert_eq!(back, p);
        let mut tag2 = [0u8; 8];
        d.tag(&mut tag2, 8);
        assert_eq!(tag, tag2);
    }
    let mut c = Ccm {
        nonce: [0; 16],
        cmac: [0; 16],
        blocks: 0,
    };
    c.init(8, 2);
    assert_eq!(c.setiv(&nonce[..10], 5), -1);
    c.setiv(&nonce, 5);
    let mut out = [0u8; 4];
    assert_eq!(c.encrypt(&[0; 4], &mut out, &e), -1);
}

/// IEEE 1619 XTS-AES-128 vector 1, and stealing both ways.
#[test]
fn xts_known_answer_and_stealing() {
    let (e, d) = aes("00000000000000000000000000000000");
    let mut out = [0u8; 32];
    assert_eq!(xts(&[0; 16], &[0; 32], &mut out, true, &e, &e), 0);
    assert_eq!(
        hex(&out),
        "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"
    );
    let data: Vec<u8> = (0..70u8).collect();
    for len in 16..=70 {
        let mut c = vec![0; len];
        assert_eq!(xts(&[7; 16], &data[..len], &mut c, true, &e, &e), 0);
        let mut p = vec![0; len];
        assert_eq!(xts(&[7; 16], &c, &mut p, false, &d, &e), 0);
        assert_eq!(p, &data[..len], "{len}");
    }
    assert_eq!(xts(&[0; 16], &[0; 15], &mut out, true, &e, &e), -1);
}

/// RFC 7253 sample results: empty, and 8 octets of AAD and plaintext.
#[test]
fn ocb_known_answers() {
    let (e, d) = aes("000102030405060708090a0b0c0d0e0f");
    let mut o = Ocb::new(&e);
    assert_eq!(o.setiv(&unhex("bbaa99887766554433221100"), 16, &e), 1);
    let mut tag = [0u8; 16];
    assert_eq!(o.tag(&mut tag, &e), 1);
    assert_eq!(hex(&tag), "785407bfffc8ad9edcc5520ac9111ee6");
    assert_eq!(o.finish(&tag, &e), 0);
    assert_eq!(o.finish(&tag[..0], &e), -1);

    let mut o = Ocb::new(&e);
    o.setiv(&unhex("bbaa99887766554433221101"), 16, &e);
    let x = unhex("0001020304050607");
    o.aad(&x, &e);
    let mut c = [0u8; 8];
    o.encrypt(&x, &mut c, &e, &d, None);
    o.tag(&mut tag, &e);
    assert_eq!(hex(&c), "6820b3657b6f615a");
    assert_eq!(hex(&tag), "5725bda0d3b4eb3a257c9af1f8f03009");
    let mut o = Ocb::new(&e);
    o.setiv(&unhex("bbaa99887766554433221101"), 16, &e);
    o.aad(&x, &e);
    let mut p = [0u8; 8];
    o.decrypt(&c, &mut p, &e, &d, None);
    assert_eq!(p.as_slice(), x.as_slice());
    assert_eq!(o.finish(&tag, &e), 0);
    assert_eq!(o.setiv(&[0; 16], 16, &e), -1);
    assert_eq!(o.setiv(&[0; 12], 0, &e), -1);
}
