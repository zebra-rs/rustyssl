//! TLS 1.2's SRP key exchange (RFC 5054, OpenSSL's `tls_srp.c`): the checks the core makes on
//! the numbers exchanged. The numbers themselves (B, A, the premaster secrets) are made by the
//! application's side ([`crate::conn::Request::SrpUsername`] and the other SRP requests),
//! which holds the connection's SRP state and runs its callbacks.

use core::cmp::Ordering;

use rustyssl_abi as abi;

use crate::conn::common::ask_once;
use crate::conn::{Answer, Connection, Request, SrpParams};
use crate::error::{Error, InFunc, Result};

/// A big-endian number without its leading zeros (`BN_bin2bn`'s value).
fn trimmed(n: &[u8]) -> &[u8] {
    let lead = n.iter().take_while(|&&b| b == 0).count();
    n.get(lead..).unwrap_or_default()
}

/// `BN_ucmp` of two big-endian numbers.
pub(crate) fn cmp(a: &[u8], b: &[u8]) -> Ordering {
    let (a, b) = (trimmed(a), trimmed(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// `BN_is_zero`.
pub(crate) fn is_zero(n: &[u8]) -> bool {
    trimmed(n).is_empty()
}

/// `BN_num_bits`.
fn num_bits(n: &[u8]) -> usize {
    let n = trimmed(n);
    let lead = n
        .first()
        .map_or(0, |b| 8usize.saturating_sub(b.leading_zeros() as usize));
    n.len()
        .saturating_sub(1)
        .saturating_mul(8)
        .saturating_add(lead)
}

/// `srp_verify_server_param`: g and B below N, B not zero (`SSL_R_BAD_DATA`,
/// illegal-parameter), N of at least the configured strength, then the verify-parameter
/// callback (`SSL_R_CALLBACK_FAILED`) or, without one, a known group
/// (`SSL_R_INSUFFICIENT_SECURITY`), both insufficient-security. `false` while waiting.
///
/// # Errors
/// As above.
pub(crate) fn verify_server_param(c: &mut Connection, params: &SrpParams) -> Result<bool> {
    verify_server_param_inner(c, params).in_func("srp_verify_server_param")
}

/// See [`verify_server_param`].
fn verify_server_param_inner(c: &mut Connection, params: &SrpParams) -> Result<bool> {
    if cmp(&params.g, &params.n) != Ordering::Less
        || cmp(&params.b, &params.n) != Ordering::Less
        || is_zero(&params.b)
    {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_DATA,
        ));
    }
    let strength = usize::try_from(c.cfg.srp_strength).unwrap_or(0);
    if num_bits(&params.n) < strength {
        return Err(Error::alert(
            abi::SSL_AD_INSUFFICIENT_SECURITY,
            abi::SSL_R_INSUFFICIENT_SECURITY,
        ));
    }
    let Some(a) = ask_once(c, Request::SrpVerifyParams(params.clone()), 0) else {
        return Ok(false);
    };
    match a {
        Answer::SrpVerified(1) => Ok(true),
        Answer::SrpVerified(0) => Err(Error::alert(
            abi::SSL_AD_INSUFFICIENT_SECURITY,
            abi::SSL_R_CALLBACK_FAILED,
        )),
        Answer::SrpVerified(_) => Err(Error::alert(
            abi::SSL_AD_INSUFFICIENT_SECURITY,
            abi::SSL_R_INSUFFICIENT_SECURITY,
        )),
        _ => Err(Error::internal()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_compare_by_value() {
        assert_eq!(cmp(&[0, 0, 5], &[5]), Ordering::Equal);
        assert_eq!(cmp(&[1, 0], &[0xff]), Ordering::Greater);
        assert_eq!(cmp(&[0x7f], &[0, 0x80]), Ordering::Less);
        assert!(is_zero(&[0, 0]));
        assert!(is_zero(&[]));
        assert!(!is_zero(&[0, 1]));
        assert_eq!(num_bits(&[0, 0x80, 0]), 16);
        assert_eq!(num_bits(&[1]), 1);
        assert_eq!(num_bits(&[]), 0);
    }
}
