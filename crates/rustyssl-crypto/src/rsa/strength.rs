//! `ossl_ifc_ffc_compute_security_bits` (`rsa_lib.c`): the security strength of an IFC (RSA)
//! or FFC (DH, DSA) modulus of `n` bits, SP 800-56B rev 2 Appendix D's estimate, in OpenSSL's
//! 64-bit fixed-point arithmetic so every value comes out as OpenSSL's does.

/// The fixed point's scale, 2^18.
const SCALE: u64 = 1 << 18;
/// The cube root of the scale.
const CBRT_SCALE: u64 = 1 << (2 * 18 / 3);
/// scale * ln(2).
const LOG_2: u64 = 0x02c5c8;
/// scale * log2(e).
const LOG_E: u64 = 0x05c551;
/// scale * 1.923.
const C1_923: u64 = 0x07b126;
/// scale * 4.690.
const C4_690: u64 = 0x12c28f;

/// Two scaled numbers multiplied and rescaled (`mul2`; the C's `uint64_t`).
fn mul2(a: u64, b: u64) -> u64 {
    a.wrapping_mul(b) / SCALE
}

/// The cube root of a scaled number (`icbrt64`).
fn icbrt64(mut x: u64) -> u64 {
    let mut r: u64 = 0;
    for s in (0..=63).rev().step_by(3) {
        r = r.wrapping_shl(1);
        let b = 3u64
            .wrapping_mul(r)
            .wrapping_mul(r.wrapping_add(1))
            .wrapping_add(1);
        if (x >> s) >= b {
            x = x.wrapping_sub(b.wrapping_shl(s));
            r = r.wrapping_add(1);
        }
    }
    r.wrapping_mul(CBRT_SCALE)
}

/// The natural logarithm of a scaled number greater than one (`ilog_e`).
fn ilog_e(mut v: u64) -> u64 {
    let mut r: u64 = 0;
    while v >= 2 * SCALE {
        v >>= 1;
        r = r.wrapping_add(SCALE);
    }
    let mut i = SCALE / 2;
    while i != 0 {
        v = mul2(v, v);
        if v >= 2 * SCALE {
            v >>= 1;
            r = r.wrapping_add(i);
        }
        i /= 2;
    }
    // The C keeps r in 32 bits.
    (r & 0xffff_ffff).wrapping_mul(SCALE) / LOG_E
}

/// `ossl_ifc_ffc_compute_security_bits`.
pub fn ifc_ffc_security_bits(n: usize) -> u16 {
    match n {
        2048 => return 112,
        3072 => return 128,
        4096 => return 152,
        6144 => return 176,
        7680 => return 192,
        8192 => return 200,
        15360 => return 256,
        _ => {}
    }
    if n >= 687_737 {
        return 1200;
    }
    if n < 8 {
        return 0;
    }
    let cap: u16 = if n <= 7680 {
        192
    } else if n <= 15360 {
        256
    } else {
        1200
    };
    let x = u64::try_from(n).unwrap_or(0).wrapping_mul(LOG_2);
    let lx = ilog_e(x) & 0xffff_ffff;
    let t = mul2(C1_923, icbrt64(mul2(mul2(x, lx), lx))).wrapping_sub(C4_690) / LOG_2;
    let y = u16::try_from(t & 0xffff).unwrap_or(0);
    let y = y.wrapping_add(4) & !7;
    y.min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_strengths() {
        // The canonical ones, and the formula's (1024 → 80, as OpenSSL's).
        for (n, s) in [
            (2048, 112),
            (3072, 128),
            (1024, 80),
            (512, 56),
            (7, 0),
            (700_000, 1200),
        ] {
            assert_eq!(ifc_ffc_security_bits(n), s, "{n}");
        }
    }
}
