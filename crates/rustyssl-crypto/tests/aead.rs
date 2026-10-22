//! The AEAD contexts (`provided::aead`) against vectors from the reference OpenSSL
//! (`tests/data/aead_vectors.txt`): GCM, CCM, OCB, and ChaCha20-Poly1305 with several IV and
//! tag lengths, AAD and data given in pieces of every size up to 40 octets (CCM in one, as it
//! takes them), decrypted back, and with a tag that doesn't authenticate.

#[cfg(test)]
mod tests {
    use rustyssl_crypto::provided::aead::{Ccm, ChaChaPoly, Gcm, Io, Ocb};
    use rustyssl_crypto::provided::cipher::Output;
    use rustyssl_crypto::sym::BlockAlgorithm;

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[allow(clippy::large_enum_variant)] // GCM keeps its keyed GHASH; only a test holds these
    enum Aead {
        Gcm(Gcm),
        Ccm(Ccm),
        Ocb(Ocb),
        ChaChaPoly(ChaChaPoly),
    }

    fn make(name: &str, ivlen: usize, taglen: usize) -> Aead {
        let bits = |n: &str| -> usize {
            n.split('-')
                .nth(1)
                .and_then(|b| b.parse::<usize>().ok())
                .map_or(16, |b| b / 8)
        };
        let alg = if name.starts_with("ARIA") {
            BlockAlgorithm::Aria
        } else if name.starts_with("SM4") {
            BlockAlgorithm::Sm4
        } else {
            BlockAlgorithm::Aes
        };
        if name.ends_with("GCM") {
            let mut g = Gcm::new(alg, bits(name));
            g.set_iv_len(ivlen).unwrap();
            Aead::Gcm(g)
        } else if name.ends_with("CCM") {
            let mut g = Ccm::new(alg, bits(name));
            g.set_iv_len(ivlen).unwrap();
            g.set_tag(None, taglen).unwrap();
            Aead::Ccm(g)
        } else if name.ends_with("OCB") {
            let mut g = Ocb::new(bits(name));
            g.set_iv_len(ivlen).unwrap();
            g.set_tag(None, taglen).unwrap();
            Aead::Ocb(g)
        } else {
            Aead::ChaChaPoly(ChaChaPoly::new())
        }
    }

    fn io(input: Option<&[u8]>, inl: usize, out: bool) -> Io<'_> {
        Io {
            input,
            inl,
            out,
            in_place: false,
            outsize: inl + 16,
        }
    }

    impl Aead {
        fn init(&mut self, enc: bool, key: &[u8], iv: &[u8]) {
            match self {
                Aead::Gcm(g) => g.init(enc, Some(key), Some(iv)),
                Aead::Ccm(g) => g.init(enc, Some(key), Some(iv)),
                Aead::Ocb(g) => g.init(enc, Some(key), Some(iv)),
                Aead::ChaChaPoly(g) => g.init(enc, Some(key), Some(iv)),
            }
            .unwrap();
        }

        fn update(&mut self, io: Io<'_>) -> Output {
            match self {
                Aead::Gcm(g) => g.update(io).unwrap(),
                Aead::Ccm(g) => g.update(io).unwrap(),
                Aead::Ocb(g) => g.update(io).unwrap(),
                Aead::ChaChaPoly(g) => g.update(io).unwrap(),
            }
        }

        fn finalize(&mut self) -> Result<Output, ()> {
            match self {
                Aead::Gcm(g) => g.finalize().map_err(|_| ()),
                Aead::Ccm(g) => g.finalize().map_err(|_| ()),
                Aead::Ocb(g) => g.finalize().map_err(|_| ()),
                Aead::ChaChaPoly(g) => g.finalize().map_err(|_| ()),
            }
        }

        fn tag(&mut self, n: usize) -> Vec<u8> {
            match self {
                Aead::Gcm(g) => g.tag(n).unwrap().to_vec(),
                Aead::Ccm(g) => g.tag(n).unwrap(),
                Aead::Ocb(g) => g.tag(n).unwrap().to_vec(),
                Aead::ChaChaPoly(g) => g.tag(n).unwrap().to_vec(),
            }
        }

        fn set_tag(&mut self, t: &[u8]) {
            match self {
                Aead::Gcm(g) => g.set_tag(t),
                Aead::Ccm(g) => g.set_tag(Some(t), t.len()),
                Aead::Ocb(g) => g.set_tag(Some(t), t.len()),
                Aead::ChaChaPoly(g) => g.set_tag(Some(t), t.len()),
            }
            .unwrap();
        }

        fn is_ccm(&self) -> bool {
            matches!(self, Aead::Ccm(_))
        }
    }

    /// One pass: AAD and data in pieces (CCM: its length first, then each whole). Returns the
    /// output and whether the final succeeded.
    fn pass(a: &mut Aead, aad: &[u8], data: &[u8], piece: usize) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        if a.is_ccm() {
            a.update(io(None, data.len(), false));
            if !aad.is_empty() {
                a.update(io(Some(aad), aad.len(), false));
            }
            let o = a.update(io(Some(data), data.len(), true));
            if o.failed.is_some() {
                return (o.data.to_vec(), false);
            }
            out.extend_from_slice(&o.data);
        } else {
            for c in aad.chunks(piece) {
                a.update(io(Some(c), c.len(), false));
            }
            for c in data.chunks(piece) {
                let o = a.update(io(Some(c), c.len(), true));
                out.extend_from_slice(&o.data);
            }
        }
        match a.finalize() {
            Ok(o) if o.failed.is_none() => {
                out.extend_from_slice(&o.data);
                (out, true)
            }
            Ok(o) => {
                out.extend_from_slice(&o.data);
                (out, false)
            }
            Err(()) => (out, false),
        }
    }

    #[test]
    fn vectors() {
        let text = include_str!("data/aead_vectors.txt");
        let mut count = 0;
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let (key, iv, aad, pt, ct, tag) = (
                unhex(f[1]),
                unhex(f[2]),
                unhex(f[3]),
                unhex(f[4]),
                unhex(f[5]),
                unhex(f[6]),
            );
            for piece in [1, 3, 5, 15, 16, 17, 31, 40] {
                let mut e = make(f[0], iv.len(), tag.len());
                e.init(true, &key, &iv);
                let (out, ok) = pass(&mut e, &aad, &pt, piece);
                assert!(ok, "{line} {piece}");
                assert_eq!(out, ct, "{line} {piece}");
                assert_eq!(e.tag(tag.len()), tag, "{line} {piece}");

                let mut d = make(f[0], iv.len(), tag.len());
                d.init(false, &key, &iv);
                d.set_tag(&tag);
                let (back, ok) = pass(&mut d, &aad, &ct, piece);
                assert!(ok, "{line} {piece}");
                assert_eq!(back, pt, "{line} {piece}");

                let mut bad = tag.clone();
                bad[0] ^= 1;
                let mut d = make(f[0], iv.len(), tag.len());
                d.init(false, &key, &iv);
                d.set_tag(&bad);
                let (back, ok) = pass(&mut d, &aad, &ct, piece);
                assert!(!ok, "{line} {piece}: a bad tag fails");
                if f[0].ends_with("CCM") {
                    assert!(back.iter().all(|&b| b == 0), "CCM wipes its output");
                }
            }
            count += 1;
        }
        assert_eq!(count, 48);
    }

    /// docs/DEVIATIONS.md: a TLS fixed IV or inverted IV longer than GCM's IV fails; the
    /// reference copies it over the context.
    #[test]
    fn gcm_tls_ivs_longer_than_the_iv() {
        let key = [7u8; 16];
        let mut g = Gcm::new(BlockAlgorithm::Aes, 16);
        g.init(true, Some(&key), None).unwrap();
        assert!(g.tls_iv_fixed(&[1; 13], false).is_err());
        assert!(g.tls_iv_fixed(&[1; 200], false).is_err());
        assert!(g.tls_iv_fixed(&[1; 4], false).is_ok());

        let mut g = Gcm::new(BlockAlgorithm::Aes, 16);
        g.init(false, Some(&key), None).unwrap();
        g.tls_iv_fixed(&[1; 4], false).unwrap();
        assert!(g.set_iv_inv(&[2; 13]).is_err());
        assert!(g.set_iv_inv(&[2; 100]).is_err());
        assert!(g.set_iv_inv(&[2; 8]).is_ok());
    }
}
