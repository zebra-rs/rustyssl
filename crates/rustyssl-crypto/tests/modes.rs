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
}
