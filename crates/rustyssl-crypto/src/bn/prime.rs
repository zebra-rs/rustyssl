//! Prime testing's fixed parts (`bn_prime.c`, `bn_prime.h`): the first 2048 primes, which
//! OpenSSL's trial division and candidate sieve use, and how many of them and how many
//! Miller-Rabin rounds it takes for a size. The tests themselves draw random numbers and call
//! back into the application, so they run in the C layer.

/// `NUMPRIMES`.
pub const NUMPRIMES: usize = 2048;

/// The first [`NUMPRIMES`] primes (`primes` in `bn_prime.h`, which `bn_prime.pl` generates).
pub const PRIMES: [u16; NUMPRIMES] = first_primes();

/// The first [`NUMPRIMES`] primes, by trial division at compile time (a fault here is a build
/// error, not a panic at run time).
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of,
    reason = "evaluated only at compile time, on numbers below 2^16"
)]
const fn first_primes() -> [u16; NUMPRIMES] {
    let mut out = [0u16; NUMPRIMES];
    let mut count = 0;
    let mut n: u32 = 2;
    while count < NUMPRIMES {
        let mut d: u32 = 2;
        let mut prime = true;
        while d * d <= n {
            if n % d == 0 {
                prime = false;
                break;
            }
            d += 1;
        }
        if prime {
            out[count] = n as u16;
            count += 1;
        }
        n += 1;
    }
    out
}

/// `calc_trial_divisions`: how many of the primes trial division uses for a number of `bits`.
pub fn trial_divisions(bits: usize) -> usize {
    if bits <= 512 {
        64
    } else if bits <= 1024 {
        128
    } else if bits <= 2048 {
        384
    } else if bits <= 4096 {
        1024
    } else {
        NUMPRIMES
    }
}

/// `bn_mr_min_checks`: the fewest Miller-Rabin rounds for a number of `bits`.
pub fn min_checks(bits: usize) -> i32 {
    if bits > 2048 { 128 } else { 64 }
}
