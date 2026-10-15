//! Fuzzes the decoding of elliptic-curve points (`EC_POINT_oct2point`), which sees the points
//! peers send in key exchanges and certificates. The first octet picks a built-in curve, and
//! the rest is the encoding. Nothing may panic, and a point that decodes:
//!
//! - is on the curve;
//! - encodes back, in its own form, to exactly the octets it came from;
//! - multiplied by the group's order times its cofactor, is the point at infinity.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::bn;
use rustyssl_crypto::ec::{Group, Point, curves, mult, oct, point};

/// A fixed stream of "random" octets: the operations only blind with them.
fn stream() -> impl FnMut(&mut [u8]) -> bool {
    let mut x: u32 = 0x9e37_79b9;
    move |out: &mut [u8]| {
        for b in out {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x.to_le_bytes()[0];
        }
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, enc)) = data.split_first() else {
        return;
    };
    let all = curves::builtin();
    let curve = &all[usize::from(pick) % all.len()];
    let Ok(g) = Group::from_curve(curve) else {
        return;
    };
    let mut rng = stream();
    let mut p = Point::infinity();
    if oct::decode(&g, &mut p, enc, &mut rng).is_err() {
        return;
    }
    assert!(
        point::is_on_curve(&g, &p).unwrap_or(false),
        "decoded point not on the curve"
    );
    // Infinity (a lone zero) encodes the same in every form, but not in "form" zero.
    let form = match enc[0] & !1 {
        0 => oct::COMPRESSED,
        f => f,
    };
    let again = oct::encode(&g, &p, form, &mut rng).expect("re-encoding a decoded point");
    assert_eq!(again, enc, "re-encoding differs");
    let n = bn::mul(&g.order, &g.cofactor).expect("order times cofactor");
    let mut r = Point::infinity();
    let pairs = [(&p, &n)];
    let req = mult::Request {
        scalar: None,
        pairs: &pairs,
        scalar_is_order: false,
    };
    mult::mul(&g, &mut r, &req, &mut rng).expect("multiplying a decoded point");
    assert!(
        r.is_at_infinity(),
        "order times cofactor times a point isn't infinity"
    );
});
