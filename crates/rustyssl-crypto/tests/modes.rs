//! The other modes (`provided::cipher`'s CTS, XTS, and key wraps; `provided::siv`) against
//! vectors from the reference OpenSSL (`tests/data/mode_vectors.txt`): each encrypted as the
//! reference did, then decrypted back, and SIV and GCM-SIV with a tag that doesn't
//! authenticate.

#[cfg(test)]
mod tests {
    use rustyssl_crypto::provided::aead::Io;
    use rustyssl_crypto::provided::cipher::{Ctx, Kind, Mode};
    use rustyssl_crypto::provided::siv::{GcmSiv, Siv};
    use rustyssl_crypto::sym::BlockAlgorithm;

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// The cipher a name stands for, with its key length.
    fn kind(name: &str, keylen: usize) -> Kind {
        let algorithm = if name.starts_with("CAMELLIA") {
            BlockAlgorithm::Camellia
        } else if name.starts_with("SM4") {
            BlockAlgorithm::Sm4
        } else {
            BlockAlgorithm::Aes
        };
        let mode = if name.ends_with("CTS") {
            Mode::CbcCts
        } else if name.ends_with("XTS") {
            Mode::Xts
        } else if name.ends_with("WRAP-PAD-INV") {
            Mode::WrapPadInv
        } else if name.ends_with("WRAP-PAD") {
            Mode::WrapPad
        } else if name.ends_with("WRAP-INV") {
            Mode::WrapInv
        } else {
            Mode::Wrap
        };
        Kind::Block {
            algorithm,
            key_len: keylen,
            mode,
        }
    }

    fn io(input: &[u8], room: usize) -> Io<'_> {
        Io {
            input: Some(input),
            inl: input.len(),
            out: true,
            in_place: false,
            outsize: room,
        }
    }

    /// One pass of a generic-context mode.
    fn generic(k: Kind, variant: &str, key: &[u8], iv: &[u8], enc: bool, input: &[u8]) -> Vec<u8> {
        let mut c = Ctx::new(k);
        c.init(enc, Some(key), (!iv.is_empty()).then_some(iv))
            .unwrap();
        let g = c.generic_mut().unwrap();
        match variant {
            "CS1" => g.set_cts_mode(0),
            "CS2" => g.set_cts_mode(1),
            "CS3" => g.set_cts_mode(2),
            "GB" => g.set_xts_ieee(false),
            "IEEE" => g.set_xts_ieee(true),
            _ => {}
        }
        let room = input.len() + 16;
        let out = if k.cts() {
            c.update(input, input.len(), room).unwrap()
        } else {
            c.process(io(input, room), false).unwrap().unwrap()
        };
        assert!(out.failed.is_none() && out.raised.is_none());
        let mut data = out.data.to_vec();
        assert_eq!(out.len, data.len());
        data.extend_from_slice(
            &c.process_final()
                .unwrap_or_else(|| c.finalize(16))
                .unwrap()
                .data,
        );
        data
    }

    #[test]
    fn vectors() {
        let text = include_str!("data/mode_vectors.txt");
        let mut count = 0;
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let (name, variant, key, iv) = (f[0], f[1], unhex(f[2]), unhex(f[3]));
            let (pt, ct, tag) = (unhex(f[5]), unhex(f[6]), unhex(f[7]));
            let aad: Vec<Vec<u8>> = if f[4] == "-" {
                Vec::new()
            } else {
                f[4].split('/').map(unhex).collect()
            };
            if name.ends_with("GCM-SIV") {
                let mut e = GcmSiv::new(key.len());
                e.init(true, Some(&key), Some(&iv)).unwrap();
                for a in &aad {
                    e.cipher(Some(a), a.len(), false, a.len()).unwrap();
                }
                let o = e.cipher(Some(&pt), pt.len(), true, pt.len()).unwrap();
                assert_eq!(o.data.to_vec(), ct, "{line}");
                e.finalize().unwrap();
                assert_eq!(e.tag(16).unwrap().to_vec(), tag, "{line}");
                for good in [true, false] {
                    let mut d = GcmSiv::new(key.len());
                    d.init(false, Some(&key), Some(&iv)).unwrap();
                    let mut t = tag.clone();
                    t[3] ^= u8::from(!good);
                    d.set_tag(&t).unwrap();
                    for a in &aad {
                        d.cipher(Some(a), a.len(), false, a.len()).unwrap();
                    }
                    let o = d.cipher(Some(&ct), ct.len(), true, ct.len()).unwrap();
                    if good {
                        assert_eq!(o.data.to_vec(), pt, "{line}");
                    }
                    assert_eq!(d.finalize().is_ok(), good, "{line}");
                }
            } else if name.ends_with("SIV") {
                let mut e = Siv::new(key.len());
                e.init(true, Some(&key)).unwrap();
                for a in &aad {
                    e.cipher(Some(a), a.len(), false, a.len()).unwrap();
                }
                let o = e.cipher(Some(&pt), pt.len(), true, pt.len()).unwrap();
                assert_eq!(o.data.to_vec(), ct, "{line}");
                e.finalize().unwrap();
                assert_eq!(e.tag(16).unwrap().to_vec(), tag, "{line}");
                for good in [true, false] {
                    let mut d = Siv::new(key.len());
                    d.init(false, Some(&key)).unwrap();
                    let mut t = tag.clone();
                    t[15] ^= u8::from(!good);
                    d.set_tag(&t).unwrap();
                    for a in &aad {
                        d.cipher(Some(a), a.len(), false, a.len()).unwrap();
                    }
                    let o = d.cipher(Some(&ct), ct.len(), true, ct.len()).unwrap();
                    assert_eq!(o.failed.is_none(), good, "{line}");
                    if good {
                        assert_eq!(o.data.to_vec(), pt, "{line}");
                    } else {
                        assert!(o.data.iter().all(|&b| b == 0), "a bad tag wipes the output");
                    }
                    assert_eq!(d.finalize().is_ok(), good, "{line}");
                }
            } else {
                let k = kind(name, key.len());
                assert_eq!(generic(k, variant, &key, &iv, true, &pt), ct, "{line}");
                assert_eq!(generic(k, variant, &key, &iv, false, &ct), pt, "{line}");
            }
            count += 1;
        }
        assert_eq!(count, 324);
    }

    /// An AES key wrap that doesn't unwrap fails with zeros where the reference wipes, reported
    /// as success of `SIZE_MAX` octets with an error raised.
    #[test]
    fn unwrapping_garbage_fails() {
        for (mode, wiped) in [(Mode::Wrap, 16), (Mode::WrapPad, 24)] {
            let k = Kind::Block {
                algorithm: BlockAlgorithm::Aes,
                key_len: 16,
                mode,
            };
            let mut c = Ctx::new(k);
            c.init(false, Some(&[1; 16]), None).unwrap();
            let o = c.process(io(&[2; 24], 32), false).unwrap().unwrap();
            assert_eq!(o.len, usize::MAX);
            assert!(o.raised.is_some());
            assert_eq!(o.data.to_vec(), vec![0; wiped]);
        }
    }

    /// docs/DEVIATIONS.md: a copy of an XTS context without a key fails to encrypt (the
    /// reference's copy points at key schedules never set, and crashes).
    #[test]
    fn copies_of_unkeyed_xts_fail() {
        for algorithm in [BlockAlgorithm::Aes, BlockAlgorithm::Sm4] {
            let k = Kind::Block {
                algorithm,
                key_len: 32,
                mode: Mode::Xts,
            };
            let mut c = Ctx::new(k);
            c.init(true, None, Some(&[7; 16])).unwrap();
            let mut copy = c.clone();
            let r = copy.process(io(&[1; 32], 48), false).unwrap();
            assert!(r.is_err());
        }
    }

    /// AES-128-CBC-HMAC-SHA1 with a TLS 1.0 AAD (upstream's evpciph_aes_stitched.txt, line 1):
    /// the record encrypts as the reference's, and its decryption's `update`, with
    /// `tls-version` set, leaves out the padding and the MAC (TLS 1.0 has no explicit IV), as
    /// `ossl_cipher_generic_stream_update` does; each SSL 3.0 or TLS 1.0 setting takes a block
    /// off what it leaves out, until less than a block is left.
    #[test]
    fn composite_tls_version() {
        let k = Kind::Block {
            algorithm: BlockAlgorithm::Aes,
            key_len: 16,
            mode: Mode::CbcHmacSha1,
        };
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let mac_key = unhex("cafebabefacedbaddecaf88801020304");
        let iv = unhex("101112131415161718191a1b1c1d1e1f");
        let aad = unhex("90a1b2c3e4f506172803010050");
        let pt = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f",
        );
        let ct = unhex(
            "18bd54842828fdc0ac5a3b459f32f0be305a77944b17f62fedd4442ae60a0b0a\
             3e1c2c23c584c86877fbd9997b415959254ea06ef046dc2e1fdafe7950a77ba9\
             4494683e01a0c495dc223a2de73be147d3f2b4f8d4d1e35487059ddc688544a0\
             4dbacd1405a7b3871c3a2ab7c71c663d",
        );
        let record = |enc: bool, version: Option<u32>, input: &[u8]| {
            let mut c = Ctx::new(k);
            c.init(enc, Some(&key), Some(&iv)).unwrap();
            let g = c.generic_mut().unwrap();
            g.set_mac_key(&mac_key).unwrap();
            if let Some(v) = version {
                g.set_composite_tls_version(v).unwrap();
            }
            let mut a = aad.clone();
            g.set_composite_tls_aad(&mut a).unwrap();
            let mut data = input.to_vec();
            if enc {
                data.resize(ct.len(), 0);
            }
            let out = c.process(io(&data, data.len()), false).unwrap().unwrap();
            assert!(out.failed.is_none());
            let mut d = out.data.to_vec();
            d.truncate(out.len);
            d
        };
        assert_eq!(record(true, None, &pt), ct);
        // The AAD's record length, 0x50: the rest of `pt` is the room for the MAC and padding.
        assert_eq!(record(false, Some(0x0301), &ct), pt[..0x50]);
        assert_eq!(record(false, None, &ct).len(), ct.len());

        let mut c = Ctx::new(k);
        c.init(false, Some(&key), Some(&iv)).unwrap();
        let g = c.generic_mut().unwrap();
        g.set_composite_tls_version(0x0303).unwrap();
        g.set_composite_tls_version(0x0301).unwrap();
        g.set_composite_tls_version(0x0300).unwrap();
        assert!(g.set_composite_tls_version(0x0301).is_err());
    }
}
