//! The cipher-string parser and the suite table against OpenSSL 3.5.9's own answers.
//!
//! The data files come from the reference's `openssl ciphers` (generated once; see each file's
//! producer described below), which does: `SSL_CTX_new(TLS_server_method())`, then
//! `SSL_CTX_set_ciphersuites` if asked, then `SSL_CTX_set_cipher_list` if a string is given,
//! and prints `SSL_get_ciphers` of a new `SSL`.
//!
//! - `cipherstrings.txt`: `case <rule>` then `ok <names>` or `err <reasons>`.
//! - `ciphersuites.txt`: `case <ciphersuites>` then two results: with the default list, and
//!   with `kRSA`.
//! - `descriptions.txt`: `-V` output for every suite the reference offers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::ffi::c_int;

use rustyssl_tls::cipherstring::{self, Available, CertSettings, Method};
use rustyssl_tls::suites::{self, Cipher};

const CIPHERSTRINGS: &str = include_str!("data/cipherstrings.txt");
const CIPHERSUITES: &str = include_str!("data/ciphersuites.txt");
const DESCRIPTIONS: &str = include_str!("data/descriptions.txt");

/// OpenSSL's text for a reason, as its error lines print it.
fn reason_text(r: c_int) -> &'static str {
    match r {
        rustyssl_abi::SSL_R_INVALID_COMMAND => "invalid command",
        rustyssl_abi::SSL_R_NO_CIPHER_MATCH => "no cipher match",
        rustyssl_abi::SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE => {
            "at least TLS 1.2 needed in suiteB mode"
        }
        _ => "other",
    }
}

/// An `SSL_CTX` as far as its cipher lists go.
struct Ctx {
    available: Available,
    tls13: Vec<&'static Cipher>,
    list: Vec<&'static Cipher>,
    cert: CertSettings,
}

impl Ctx {
    /// `SSL_CTX_new`: the default TLS 1.3 suites and the default list.
    fn new() -> Self {
        let available = Available::default_provider();
        let mut tls13 =
            cipherstring::parse_ciphersuites(cipherstring::DEFAULT_CIPHERSUITES.to_str().unwrap())
                .unwrap();
        let mut cert = CertSettings::default();
        let list = cipherstring::build(
            &available,
            Method::TLS,
            &mut tls13,
            cipherstring::DEFAULT_CIPHER_LIST.to_str().unwrap(),
            &mut cert,
        )
        .unwrap();
        Self {
            available,
            tls13,
            list,
            cert,
        }
    }

    /// `SSL_CTX_set_cipher_list`: on success (or no TLS 1.2 match) the new list is installed.
    fn set_cipher_list(&mut self, rule: &str) -> Result<(), Vec<c_int>> {
        match cipherstring::build(
            &self.available,
            Method::TLS,
            &mut self.tls13,
            rule,
            &mut self.cert,
        ) {
            Err(e) => Err(e.raised),
            Ok(list) => {
                self.list = list;
                if cipherstring::count_tls12(&self.list) == 0 {
                    Err(vec![rustyssl_abi::SSL_R_NO_CIPHER_MATCH])
                } else {
                    Ok(())
                }
            }
        }
    }

    /// `SSL_CTX_set_ciphersuites`.
    fn set_ciphersuites(&mut self, s: &str) -> Result<(), Vec<c_int>> {
        let parsed = cipherstring::parse_ciphersuites(s).map_err(|e| vec![e.reason])?;
        self.tls13 = parsed;
        self.list = cipherstring::replace_tls13(&self.available, &self.list, &self.tls13);
        Ok(())
    }

    fn names(&self) -> String {
        self.list
            .iter()
            .map(|c| c.name_str())
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// What a result line should say.
fn render(r: Result<String, Vec<c_int>>) -> String {
    match r {
        Ok(names) => format!("ok {names}"),
        Err(reasons) => format!(
            "err {}",
            reasons
                .iter()
                .map(|&r| reason_text(r))
                .collect::<Vec<_>>()
                .join("|")
        ),
    }
}

#[test]
fn cipher_strings_give_the_references_lists() {
    let mut lines = CIPHERSTRINGS.lines();
    let mut cases = 0;
    let mut failures = Vec::new();
    while let Some(case) = lines.next() {
        let rule = case
            .strip_prefix("case ")
            .unwrap_or_else(|| panic!("bad case line {case:?}"));
        let want = lines.next().unwrap();
        let mut ctx = Ctx::new();
        let got = render(ctx.set_cipher_list(rule).map(|()| ctx.names()));
        if got != want {
            failures.push(format!("{rule:?}\n  want {want}\n  got  {got}"));
        }
        cases += 1;
    }
    assert!(cases >= 100, "only {cases} cases");
    assert!(
        failures.is_empty(),
        "{} of {cases} differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn ciphersuite_strings_give_the_references_lists() {
    let mut lines = CIPHERSUITES.lines();
    let mut failures = Vec::new();
    while let Some(case) = lines.next() {
        let cs = case.strip_prefix("case ").unwrap();
        for rule in [None, Some("kRSA")] {
            let want = lines.next().unwrap();
            let mut ctx = Ctx::new();
            let r = ctx.set_ciphersuites(cs).and_then(|()| match rule {
                Some(r) => ctx.set_cipher_list(r),
                None => Ok(()),
            });
            let got = render(r.map(|()| ctx.names()));
            if got != want {
                failures.push(format!("{cs:?} with {rule:?}\n  want {want}\n  got  {got}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn descriptions_and_ids_are_the_references() {
    let mut n = 0;
    for line in DESCRIPTIONS.lines() {
        // "          0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 Kx=ECDH ..."
        let (ids, desc) = line.trim_start().split_once(" - ").unwrap();
        let (hi, lo) = ids.split_once(',').unwrap();
        let hi = u16::from_str_radix(hi.trim_start_matches("0x"), 16).unwrap();
        let lo = u16::from_str_radix(lo.trim_start_matches("0x"), 16).unwrap();
        let c = suites::by_protocol_id((hi << 8) | lo).unwrap_or_else(|| panic!("no suite {ids}"));
        assert_eq!(c.description(), format!("{desc}\n"), "{ids}");
        n += 1;
    }
    // The 7 TLS 1.3 suites and the 155 others the default provider can do.
    assert_eq!(n, 162);
}

#[test]
fn the_default_list_is_the_references() {
    let ctx = Ctx::new();
    let mut lines = CIPHERSTRINGS.lines();
    while let Some(case) = lines.next() {
        let want = lines.next().unwrap();
        if case == "case DEFAULT" {
            assert_eq!(format!("ok {}", ctx.names()), want);
            return;
        }
    }
    panic!("no DEFAULT case");
}

#[test]
fn seclevel_and_suiteb_change_the_settings_even_on_failure() {
    let mut ctx = Ctx::new();
    assert!(ctx.set_cipher_list("ALL:@SECLEVEL=3:@BOGUS").is_err());
    assert_eq!(ctx.cert.sec_level, 3);
    let mut ctx = Ctx::new();
    ctx.set_cipher_list("SUITEB192").unwrap();
    assert_eq!(
        ctx.names(),
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
    );
    // Once in Suite B mode, any later string is replaced by Suite B's.
    ctx.set_cipher_list("ALL").unwrap();
    assert!(ctx.names().ends_with(":ECDHE-ECDSA-AES256-GCM-SHA384"));
    assert_eq!(cipherstring::count_tls12(&ctx.list), 1);
}

#[test]
fn a_dtls_method_lists_only_dtls_suites() {
    let available = Available::default_provider();
    let mut tls13 = Vec::new();
    let mut cert = CertSettings::default();
    let list = cipherstring::build(
        &available,
        Method::DTLS,
        &mut tls13,
        "ALL:COMPLEMENTOFALL",
        &mut cert,
    )
    .unwrap();
    assert!(!list.is_empty());
    assert!(list.iter().all(|c| c.min_dtls != 0));
    assert!(
        !list
            .iter()
            .any(|c| c.name_str().contains("CHACHA") && c.min_dtls == 0)
    );
}
