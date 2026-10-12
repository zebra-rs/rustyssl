#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "test arithmetic on small known values"
)]

use super::*;

/// A deterministic generator (xorshift64*), so failures replay.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number of up to `max` limbs, with runs of zero and all-one limbs, of either sign.
    fn number(&mut self, max: usize) -> BigNum {
        let len = (self.next() % (max as u64 + 1)) as usize;
        let limbs = (0..len)
            .map(|_| match self.next() % 5 {
                0 => 0,
                1 => u64::MAX,
                _ => self.next(),
            })
            .collect();
        BigNum::from_limbs(self.next() & 1 == 1, limbs).unwrap()
    }
}

fn n(v: i128) -> BigNum {
    let m = v.unsigned_abs();
    BigNum::from_limbs(v < 0, vec![m as u64, (m >> 64) as u64]).unwrap()
}

fn hex(s: &str) -> BigNum {
    let (neg, digits) = s.strip_prefix('-').map_or((false, s), |d| (true, d));
    let mut b = BigNum::from_hex_digits(digits.as_bytes()).unwrap();
    b.set_negative(neg);
    b
}

#[test]
fn small_values_match_i128() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..2000 {
        let a = (rng.next() as i64) as i128;
        let b = (rng.next() as i64 >> (rng.next() % 64)) as i128;
        assert_eq!(add(&n(a), &n(b)).unwrap(), n(a + b));
        assert_eq!(sub(&n(a), &n(b)).unwrap(), n(a - b));
        assert_eq!(mul(&n(a), &n(b)).unwrap(), n(a * b));
        if b != 0 {
            let (q, r) = div_rem(&n(a), &n(b)).unwrap();
            assert_eq!((q, r), (n(a / b), n(a % b)), "{a} / {b}");
            assert_eq!(nnmod(&n(a), &n(b)).unwrap(), n(a.rem_euclid(b)));
        }
        assert_eq!(cmp(&n(a), &n(b)), a.cmp(&b));
        assert_eq!(ucmp(&n(a), &n(b)), a.unsigned_abs().cmp(&b.unsigned_abs()));
    }
}

#[test]
fn division_identities_hold_for_long_numbers() {
    let mut rng = Rng(0xfeed_beef_dead_cafe);
    for _ in 0..3000 {
        let a = rng.number(12);
        let mut d = rng.number(8);
        if d.is_zero() {
            d = BigNum::one();
        }
        let (q, r) = div_rem(&a, &d).unwrap();
        assert_eq!(add(&mul(&q, &d).unwrap(), &r).unwrap(), a, "{a:?} / {d:?}");
        assert_eq!(ucmp(&r, &d), Ordering::Less);
        assert!(r.is_zero() || r.is_negative() == a.is_negative());
        let m = nnmod(&a, &d).unwrap();
        assert!(!m.is_negative() && ucmp(&m, &d) == Ordering::Less);
    }
}

#[test]
fn arithmetic_identities_hold() {
    let mut rng = Rng(42);
    for _ in 0..1000 {
        let (a, b, c) = (rng.number(6), rng.number(6), rng.number(3));
        assert_eq!(sub(&add(&a, &b).unwrap(), &b).unwrap(), a);
        let left = mul(&a, &add(&b, &c).unwrap()).unwrap();
        let right = add(&mul(&a, &b).unwrap(), &mul(&a, &c).unwrap()).unwrap();
        assert_eq!(left, right);
        assert_eq!(sqr(&a).unwrap(), mul(&a, &a.abs()).unwrap().abs());
        let s = (rng.next() % 200) as usize;
        let shifted = lshift(&a, s).unwrap();
        let mut two_s = BigNum::zero();
        two_s.set_bit(s).unwrap();
        assert_eq!(shifted, mul(&a, &two_s).unwrap());
        assert_eq!(rshift(&shifted, s), a);
        let (q, _) = div_rem(&a, &two_s).unwrap();
        assert_eq!(rshift(&a, s), q);
    }
}

#[test]
fn words() {
    let mut a = n(-5);
    a.add_word(3).unwrap();
    assert_eq!(a, n(-2));
    a.add_word(7).unwrap();
    assert_eq!(a, n(5));
    a.sub_word(8).unwrap();
    assert_eq!(a, n(-3));
    a.mul_word(u64::MAX).unwrap();
    assert_eq!(a, n(-3 * u64::MAX as i128));
    assert_eq!(a.div_word(7), (3 * u64::MAX as u128 % 7) as u64);
    assert_eq!(a, n(-(3 * u64::MAX as i128 / 7)));
    assert_eq!(a.div_word(0), u64::MAX);
    assert_eq!(n(-100).mod_word(7), 2);
    let mut z = BigNum::zero();
    z.sub_word(1).unwrap();
    assert_eq!(z, n(-1));
    let mut w = n(u64::MAX as i128);
    w.add_word(1).unwrap();
    assert_eq!(w, n(1 << 64));
    w.sub_word(1).unwrap();
    assert_eq!(w, n(u64::MAX as i128));
}

#[test]
fn bits() {
    let mut a = BigNum::zero();
    a.set_bit(130).unwrap();
    assert_eq!(a.num_bits(), 131);
    assert!(a.is_bit_set(130) && !a.is_bit_set(129) && !a.is_bit_set(1000));
    assert!(!a.clear_bit(200));
    assert!(a.clear_bit(130));
    assert!(a.is_zero());
    let mut b = hex("-FFFFFFFFFFFFFFFFFF");
    assert!(!b.mask_bits(128));
    assert!(b.mask_bits(64));
    assert_eq!(b, hex("-FFFFFFFFFFFFFFFF"));
    assert!(b.mask_bits(0));
    assert!(b.is_zero() && !b.is_negative());
    assert_eq!(n(-1).get_word(), 1);
    assert_eq!(n(1 << 64).get_word(), u64::MAX);
}

#[test]
fn text() {
    assert_eq!(n(0).to_hex(), "0");
    assert_eq!(n(10).to_hex(), "0A");
    assert_eq!(n(-0x1234).to_hex(), "-1234");
    assert_eq!(n(10).to_hex_digits(), "A");
    assert_eq!(n(-0x123).to_hex_digits(), "-123");
    assert_eq!(n(0).to_hex_digits(), "0");
    assert_eq!(n(0).to_dec(), "0");
    assert_eq!(n(-1).to_dec(), "-1");
    let big = n(i128::MAX);
    assert_eq!(big.to_dec(), i128::MAX.to_string());
    let p = sub(&lshift(&BigNum::one(), 256).unwrap(), &BigNum::one()).unwrap();
    let dec = p.to_dec();
    assert_eq!(
        dec,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    );
    assert_eq!(BigNum::from_dec_digits(dec.as_bytes()).unwrap(), p);
    assert_eq!(
        BigNum::from_dec_digits(b"0000000000000000000000012").unwrap(),
        n(12)
    );
    assert_eq!(hex("fF"), n(255));
    assert_eq!(hex(&p.to_hex()), p);
}

#[test]
fn octets() {
    let a = n(0x0102);
    assert_eq!(&*a.to_bin(None, Endian::Big, false).unwrap(), &[1, 2]);
    assert_eq!(
        &*a.to_bin(Some(4), Endian::Little, false).unwrap(),
        &[2, 1, 0, 0]
    );
    assert!(a.to_bin(Some(1), Endian::Big, false).is_none());
    assert_eq!(
        BigNum::from_bin(&[0, 0, 1, 2], Endian::Big, false).unwrap(),
        a
    );
    assert_eq!(
        BigNum::from_bin(&[2, 1, 0], Endian::Little, false).unwrap(),
        a
    );
    // Two's complement.
    assert_eq!(BigNum::from_bin(&[0xff], Endian::Big, true).unwrap(), n(-1));
    assert_eq!(
        BigNum::from_bin(&[0xff, 0xff, 0x7f], Endian::Big, true).unwrap(),
        n(-129)
    );
    assert_eq!(
        BigNum::from_bin(&[0xff, 0x80], Endian::Big, true).unwrap(),
        n(-128)
    );
    assert_eq!(
        BigNum::from_bin(&[0x00, 0x80], Endian::Big, true).unwrap(),
        n(128)
    );
    assert_eq!(
        &*n(-1).to_bin(None, Endian::Big, true).unwrap(),
        &[0xff, 0xff]
    );
    assert_eq!(&*n(-128).to_bin(None, Endian::Big, true).unwrap(), &[0x80]);
    assert_eq!(
        &*n(128).to_bin(None, Endian::Big, true).unwrap(),
        &[0, 0x80]
    );
    // OpenSSL's reckoning gives a negative number whose magnitude fills its top octet no
    // extra octet.
    assert_eq!(&*n(-129).to_bin(None, Endian::Big, true).unwrap(), &[0x7f]);
    assert_eq!(
        &*n(-129).to_bin(Some(3), Endian::Big, true).unwrap(),
        &[0xff, 0xff, 0x7f]
    );
    let mut rng = Rng(7);
    for _ in 0..500 {
        let a = rng.number(5);
        let b = a.to_bin(None, Endian::Big, false).unwrap();
        assert_eq!(BigNum::from_bin(&b, Endian::Big, false).unwrap(), a.abs());
        let pad = a.num_bytes() + 9;
        let s = a.to_bin(Some(pad), Endian::Little, true).unwrap();
        assert_eq!(BigNum::from_bin(&s, Endian::Little, true).unwrap(), a);
    }
}

#[test]
fn mpi() {
    assert_eq!(&*n(0).to_mpi(), &[0, 0, 0, 0]);
    assert_eq!(&*n(0x80).to_mpi(), &[0, 0, 0, 2, 0, 0x80]);
    assert_eq!(&*n(-0x80).to_mpi(), &[0, 0, 0, 2, 0x80, 0x80]);
    assert_eq!(&*n(-1).to_mpi(), &[0, 0, 0, 1, 0x81]);
    for v in [0, 1, -1, 0x80, -0x80, 0x7fff, -0x12345678] {
        assert_eq!(BigNum::from_mpi(&n(v).to_mpi()).unwrap(), n(v));
    }
    assert_eq!(BigNum::from_mpi(&[0, 0, 0]), Err(Error::InvalidLength));
    assert_eq!(
        BigNum::from_mpi(&[0x80, 0, 0, 0]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        BigNum::from_mpi(&[0, 0, 0, 2, 1]),
        Err(Error::EncodingError)
    );
    assert_eq!(BigNum::from_mpi(&[0, 0, 0, 1, 0x80]).unwrap(), n(0));
}

#[test]
fn powers() {
    assert_eq!(exp(&n(3), &n(0)).unwrap(), n(1));
    assert_eq!(exp(&n(-3), &n(5)).unwrap(), n(-243));
    assert_eq!(exp(&n(-3), &n(-4)).unwrap(), n(81));
    assert_eq!(exp(&n(2), &n(100)).unwrap(), n(1 << 100));
}

#[test]
fn limits() {
    let mut a = BigNum::zero();
    assert_eq!(a.set_bit(MAX_LIMBS * LIMB_BITS), Err(Error::TooLong));
    assert_eq!(
        lshift(&BigNum::zero(), MAX_LIMBS * LIMB_BITS),
        Err(Error::TooLong)
    );
    assert_eq!(usub(&n(1), &n(1 << 64)), Err(Error::Arg2LtArg3));
    // A larger number of the same length wraps.
    assert_eq!(usub(&n(1), &n(2)).unwrap(), n(u64::MAX as i128));
    assert_eq!(div_rem(&n(1), &n(0)), Err(Error::DivByZero));
}

#[test]
fn swaps() {
    let (mut a, mut b) = (n(-5), n(1 << 70));
    consttime_swap(false, &mut a, &mut b, 2);
    assert_eq!((&a, &b), (&n(-5), &n(1 << 70)));
    consttime_swap(true, &mut a, &mut b, 2);
    assert_eq!((&a, &b), (&n(1 << 70), &n(-5)));
}

/// `a^p mod m` by repeated multiplication, for small exponents.
fn naive_exp(a: &BigNum, p: u64, m: &BigNum) -> BigNum {
    let m = m.abs();
    let mut r = div_rem(&BigNum::one(), &m).unwrap().1;
    for _ in 0..p {
        r = nnmod(&mul(&r, a).unwrap(), &m).unwrap();
    }
    r
}

#[test]
fn exponentiation_matches_repeated_multiplication() {
    let mut rng = Rng(99);
    for _ in 0..300 {
        let a = rng.number(4).abs();
        let mut m = rng.number(4);
        if m.is_zero() {
            m = n(7);
        }
        let p = rng.next() % 40;
        let got = modular::exp_mod(&a, &BigNum::from_word(p), &m).unwrap();
        if p == 0 {
            assert_eq!(got, modular::exp_by_zero(&m));
        } else {
            assert_eq!(got, naive_exp(&a, p, &m), "{a:?}^{p} mod {m:?}");
        }
    }
    // A long exponent against Fermat: a^(q-1) = 1 mod a prime q.
    let q = hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
    let p521 = modular::nist_prime(521).unwrap();
    let mut e = p521.clone();
    e.sub_word(1).unwrap();
    assert!(modular::exp_mod(&n(3), &e, &p521).unwrap().is_one());
    let _ = q;
}

#[test]
fn montgomery_round_trips() {
    let mut rng = Rng(5);
    for _ in 0..300 {
        let mut m = rng.number(5).abs();
        if !m.is_odd() {
            m.add_word(1).unwrap();
        }
        if m.is_one() {
            continue;
        }
        let mont = mont::Montgomery::new(&m).unwrap();
        let a = div_rem(&rng.number(5).abs(), &m).unwrap().1;
        let b = div_rem(&rng.number(5).abs(), &m).unwrap().1;
        let am = mont.to_mont(&a).unwrap();
        let bm = mont.to_mont(&b).unwrap();
        assert_eq!(mont.from_mont(&am), a);
        let prod = mont.from_mont(&mont.mul(&am, &bm).unwrap());
        assert_eq!(prod, nnmod(&mul(&a, &b).unwrap(), &m).unwrap());
    }
    assert_eq!(
        mont::Montgomery::new(&n(10)).err(),
        Some(mont::MontError::NoInverse)
    );
    assert_eq!(
        mont::Montgomery::new(&n(0)).err(),
        Some(mont::MontError::Zero)
    );
}

/// Euclid's algorithm, for comparison.
fn euclid(a: &BigNum, b: &BigNum) -> BigNum {
    let (mut a, mut b) = (a.abs(), b.abs());
    while !b.is_zero() {
        let r = div_rem(&a, &b).unwrap().1;
        a = b;
        b = r;
    }
    a
}

#[test]
fn constant_time_gcd_and_inverse() {
    let mut rng = Rng(77);
    for _ in 0..400 {
        let a = rng.number(4);
        let b = rng.number(4);
        if a.is_zero() || b.is_zero() {
            continue;
        }
        assert_eq!(ct::gcd(&a, &b).0, euclid(&a, &b), "gcd({a:?}, {b:?})");
        let m = b.abs();
        if m.is_one() {
            continue;
        }
        let x = nnmod(&a, &m).unwrap();
        let inv = ct::inverse(&x, &m);
        if euclid(&x, &m).is_one() {
            let inv = inv.expect("an inverse");
            assert!(ucmp(&inv, &m) == Ordering::Less);
            assert!(
                nnmod(&mul(&inv, &x).unwrap(), &m).unwrap().is_one(),
                "{x:?}^-1 mod {m:?}"
            );
        } else {
            assert!(inv.is_none());
        }
    }
    // An even modulus and a word: RSA's d = e^-1 mod lambda.
    let lambda = hex("D8E2B2C3A1F4B9C8E7D6A5B4C3D2E1F00123456789ABCDEF0123456789ABCDE0");
    let inv = ct::inverse(&n(65537), &lambda).unwrap();
    assert!(
        nnmod(&mul(&inv, &n(65537)).unwrap(), &lambda)
            .unwrap()
            .is_one()
    );
    assert_eq!(ct::gcd(&n(12), &n(18)).0, n(6));
    assert_eq!(ct::gcd(&n(-1 << 70), &n(1 << 66)).0, n(1 << 66));
}

#[test]
fn kronecker_symbols() {
    // (a | 7) for a in 0..7: the quadratic residues 1, 2, 4.
    let got: Vec<i32> = (0..7)
        .map(|a| modular::kronecker(&n(a), &n(7)).unwrap())
        .collect();
    assert_eq!(got, vec![0, 1, 1, -1, 1, -1, -1]);
    assert_eq!(modular::kronecker(&n(2), &n(0)).unwrap(), 0);
    assert_eq!(modular::kronecker(&n(-1), &n(0)).unwrap(), 1);
    assert_eq!(modular::kronecker(&n(4), &n(6)).unwrap(), 0);
    assert_eq!(modular::kronecker(&n(5), &n(-3)).unwrap(), -1);
}

#[test]
fn square_roots() {
    let mut never = |_: usize| -> Option<BigNum> { None };
    // e = 1 (p = 3 mod 4), e = 2 (p = 5 mod 8), and Tonelli-Shanks (p = 17, 97, 2^255 - 19).
    for p in [
        n(7),
        n(13),
        n(17),
        n(97),
        sub(&lshift(&BigNum::one(), 255).unwrap(), &n(19)).unwrap(),
    ] {
        for a in 2..30 {
            let a = n(a);
            let square = modular::mod_mul(&a, &a, &p).unwrap();
            let root = modular::mod_sqrt(&square, &p, &mut never)
                .ok()
                .expect("a root");
            assert_eq!(modular::mod_mul(&root, &root, &p).unwrap(), square);
        }
    }
    assert_eq!(
        modular::mod_sqrt(&n(3), &n(7), &mut never)
            .err()
            .map(|f| f.error),
        Some(Error::NotASquare)
    );
    assert_eq!(
        modular::mod_sqrt(&n(3), &n(9), &mut never)
            .err()
            .map(|f| f.error),
        Some(Error::PIsNotPrime)
    );
    assert_eq!(modular::mod_sqrt(&n(5), &n(2), &mut never).ok(), Some(n(1)));
}

#[test]
fn quick_forms() {
    assert_eq!(modular::mod_add_quick(&n(5), &n(4), &n(7)), n(2));
    assert_eq!(modular::mod_add_quick(&n(1), &n(2), &n(7)), n(3));
    assert_eq!(
        modular::mod_lshift_quick(&n(3), 5, &n(7)).ok(),
        Some(n(3 * 32 % 7))
    );
    assert_eq!(
        modular::mod_lshift_quick(&n(300), 1, &n(7)).err(),
        Some((Error::InputNotReduced, n(300)))
    );
    // A negative number grows past the modulus: OpenSSL stops with -10.
    assert_eq!(
        modular::mod_lshift_quick(&n(-5), 5, &n(7)).err(),
        Some((Error::InputNotReduced, n(-10)))
    );
    assert_eq!(
        modular::nist_prime(192).unwrap(),
        hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF")
    );
    assert_eq!(
        modular::nist_prime(256).unwrap().to_hex(),
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
    );
}
