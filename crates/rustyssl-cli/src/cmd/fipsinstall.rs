//! `openssl fipsinstall` (`apps/fipsinstall.c`): the FIPS provider's configuration, with the
//! module's MAC. rustyssl has no FIPS provider, so this behaves as upstream's tool does on a
//! build without one (it fails to load `fips`), and works with any provider module given.

use std::ffi::CStr;

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{
    EVP_MAX_MD_SIZE, FIPS_KEY_STRING, OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
    OSSL_PROV_FIPS_PARAM_INSTALL_MAC, OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
    OSSL_PROV_FIPS_PARAM_INSTALL_VERSION, OSSL_PROV_FIPS_PARAM_MODULE_MAC,
    OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_DRBG_TRUNC_DIGEST,
    OSSL_PROV_PARAM_DSA_SIGN_DISABLED, OSSL_PROV_PARAM_ECDH_COFACTOR_CHECK,
    OSSL_PROV_PARAM_HKDF_DIGEST_CHECK, OSSL_PROV_PARAM_HKDF_KEY_CHECK,
    OSSL_PROV_PARAM_HMAC_KEY_CHECK, OSSL_PROV_PARAM_KBKDF_KEY_CHECK,
    OSSL_PROV_PARAM_KMAC_KEY_CHECK, OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_NO_SHORT_MAC,
    OSSL_PROV_PARAM_PBKDF2_LOWER_BOUND_CHECK, OSSL_PROV_PARAM_RSA_PKCS15_PAD_DISABLED,
    OSSL_PROV_PARAM_RSA_PSS_SALTLEN_CHECK, OSSL_PROV_PARAM_RSA_SIGN_X931_PAD_DISABLED,
    OSSL_PROV_PARAM_SECURITY_CHECKS, OSSL_PROV_PARAM_SIGNATURE_DIGEST_CHECK,
    OSSL_PROV_PARAM_SSHKDF_DIGEST_CHECK, OSSL_PROV_PARAM_SSHKDF_KEY_CHECK,
    OSSL_PROV_PARAM_SSKDF_DIGEST_CHECK, OSSL_PROV_PARAM_SSKDF_KEY_CHECK,
    OSSL_PROV_PARAM_TDES_ENCRYPT_DISABLED, OSSL_PROV_PARAM_TLS1_PRF_DIGEST_CHECK,
    OSSL_PROV_PARAM_TLS1_PRF_EMS_CHECK, OSSL_PROV_PARAM_TLS1_PRF_KEY_CHECK,
    OSSL_PROV_PARAM_TLS13_KDF_DIGEST_CHECK, OSSL_PROV_PARAM_TLS13_KDF_KEY_CHECK,
    OSSL_PROV_PARAM_VERSION, OSSL_PROV_PARAM_X942KDF_KEY_CHECK,
    OSSL_PROV_PARAM_X963KDF_DIGEST_CHECK, OSSL_PROV_PARAM_X963KDF_KEY_CHECK,
    OSSL_SELF_TEST_PHASE_CORRUPT, OSSL_SELF_TEST_PHASE_FAIL, OSSL_SELF_TEST_PHASE_PASS,
    OSSL_SELF_TEST_PHASE_START,
};
use rustyssl_ossl::conf::{self, Conf};
use rustyssl_ossl::evp::{Mac, MacCtx};
use rustyssl_ossl::params::Params;
use rustyssl_ossl::provider::{self, Provider};

use crate::generated::options::fipsinstall::{OPTIONS, Opt};
use crate::lib::apps::{app_load_config, app_load_config_bio, bio_open_default, dup_bio_out};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, io};

/// `BUFSIZE`: the read size.
const BUFSIZE: usize = 4096;
/// `VERSION_VAL`.
const VERSION_VAL: &str = "1";
/// `INSTALL_STATUS_VAL`.
const INSTALL_STATUS_VAL: &str = "INSTALL_SELF_TEST_KATS_RUN";

fn s(c: &CStr) -> &str {
    c.to_str().unwrap_or_default()
}

/// `FIPS_OPTS`, in the order the configuration lists them.
#[derive(Clone, Copy)]
struct FipsOpts {
    self_test_onload: bool,
    conditional_errors: bool,
    security_checks: bool,
    hmac_key_check: bool,
    kmac_key_check: bool,
    tls_prf_ems_check: bool,
    no_short_mac: bool,
    drgb_no_trunc_dgst: bool,
    signature_digest_check: bool,
    hkdf_digest_check: bool,
    tls13_kdf_digest_check: bool,
    tls1_prf_digest_check: bool,
    sshkdf_digest_check: bool,
    sskdf_digest_check: bool,
    x963kdf_digest_check: bool,
    dsa_sign_disabled: bool,
    tdes_encrypt_disabled: bool,
    rsa_pkcs15_padding_disabled: bool,
    rsa_pss_saltlen_check: bool,
    sign_x931_padding_disabled: bool,
    hkdf_key_check: bool,
    kbkdf_key_check: bool,
    tls13_kdf_key_check: bool,
    tls1_prf_key_check: bool,
    sshkdf_key_check: bool,
    sskdf_key_check: bool,
    x963kdf_key_check: bool,
    x942kdf_key_check: bool,
    pbkdf2_lower_bound_check: bool,
    ecdh_cofactor_check: bool,
}

impl FipsOpts {
    /// `pedantic_opts`: everything on.
    const PEDANTIC: FipsOpts = FipsOpts {
        self_test_onload: true,
        conditional_errors: true,
        security_checks: true,
        hmac_key_check: true,
        kmac_key_check: true,
        tls_prf_ems_check: true,
        no_short_mac: true,
        drgb_no_trunc_dgst: true,
        signature_digest_check: true,
        hkdf_digest_check: true,
        tls13_kdf_digest_check: true,
        tls1_prf_digest_check: true,
        sshkdf_digest_check: true,
        sskdf_digest_check: true,
        x963kdf_digest_check: true,
        dsa_sign_disabled: true,
        tdes_encrypt_disabled: true,
        rsa_pkcs15_padding_disabled: true,
        rsa_pss_saltlen_check: true,
        sign_x931_padding_disabled: true,
        hkdf_key_check: true,
        kbkdf_key_check: true,
        tls13_kdf_key_check: true,
        tls1_prf_key_check: true,
        sshkdf_key_check: true,
        sskdf_key_check: true,
        x963kdf_key_check: true,
        x942kdf_key_check: true,
        pbkdf2_lower_bound_check: true,
        ecdh_cofactor_check: true,
    };

    /// `fips_opts`: the defaults, for backward compatibility.
    const DEFAULT: FipsOpts = FipsOpts {
        self_test_onload: true,
        conditional_errors: true,
        security_checks: true,
        hmac_key_check: false,
        kmac_key_check: false,
        tls_prf_ems_check: false,
        no_short_mac: false,
        drgb_no_trunc_dgst: false,
        signature_digest_check: false,
        hkdf_digest_check: false,
        tls13_kdf_digest_check: false,
        tls1_prf_digest_check: false,
        sshkdf_digest_check: false,
        sskdf_digest_check: false,
        x963kdf_digest_check: false,
        dsa_sign_disabled: false,
        tdes_encrypt_disabled: false,
        rsa_pkcs15_padding_disabled: false,
        rsa_pss_saltlen_check: false,
        sign_x931_padding_disabled: false,
        hkdf_key_check: false,
        kbkdf_key_check: false,
        tls13_kdf_key_check: false,
        tls1_prf_key_check: false,
        sshkdf_key_check: false,
        sskdf_key_check: false,
        x963kdf_key_check: false,
        x942kdf_key_check: false,
        pbkdf2_lower_bound_check: true,
        ecdh_cofactor_check: false,
    };

    /// The section's settings after `install-version`, in upstream's order.
    fn settings(&self) -> [(&'static CStr, bool); 29] {
        [
            (
                OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
                self.conditional_errors,
            ),
            (OSSL_PROV_PARAM_SECURITY_CHECKS, self.security_checks),
            (OSSL_PROV_PARAM_HMAC_KEY_CHECK, self.hmac_key_check),
            (OSSL_PROV_PARAM_KMAC_KEY_CHECK, self.kmac_key_check),
            (OSSL_PROV_PARAM_TLS1_PRF_EMS_CHECK, self.tls_prf_ems_check),
            (OSSL_PROV_PARAM_NO_SHORT_MAC, self.no_short_mac),
            (OSSL_PROV_PARAM_DRBG_TRUNC_DIGEST, self.drgb_no_trunc_dgst),
            (
                OSSL_PROV_PARAM_SIGNATURE_DIGEST_CHECK,
                self.signature_digest_check,
            ),
            (OSSL_PROV_PARAM_HKDF_DIGEST_CHECK, self.hkdf_digest_check),
            (
                OSSL_PROV_PARAM_TLS13_KDF_DIGEST_CHECK,
                self.tls13_kdf_digest_check,
            ),
            (
                OSSL_PROV_PARAM_TLS1_PRF_DIGEST_CHECK,
                self.tls1_prf_digest_check,
            ),
            (
                OSSL_PROV_PARAM_SSHKDF_DIGEST_CHECK,
                self.sshkdf_digest_check,
            ),
            (OSSL_PROV_PARAM_SSKDF_DIGEST_CHECK, self.sskdf_digest_check),
            (
                OSSL_PROV_PARAM_X963KDF_DIGEST_CHECK,
                self.x963kdf_digest_check,
            ),
            (OSSL_PROV_PARAM_DSA_SIGN_DISABLED, self.dsa_sign_disabled),
            (
                OSSL_PROV_PARAM_TDES_ENCRYPT_DISABLED,
                self.tdes_encrypt_disabled,
            ),
            (
                OSSL_PROV_PARAM_RSA_PKCS15_PAD_DISABLED,
                self.rsa_pkcs15_padding_disabled,
            ),
            (
                OSSL_PROV_PARAM_RSA_PSS_SALTLEN_CHECK,
                self.rsa_pss_saltlen_check,
            ),
            (
                OSSL_PROV_PARAM_RSA_SIGN_X931_PAD_DISABLED,
                self.sign_x931_padding_disabled,
            ),
            (OSSL_PROV_PARAM_HKDF_KEY_CHECK, self.hkdf_key_check),
            (OSSL_PROV_PARAM_KBKDF_KEY_CHECK, self.kbkdf_key_check),
            (
                OSSL_PROV_PARAM_TLS13_KDF_KEY_CHECK,
                self.tls13_kdf_key_check,
            ),
            (OSSL_PROV_PARAM_TLS1_PRF_KEY_CHECK, self.tls1_prf_key_check),
            (OSSL_PROV_PARAM_SSHKDF_KEY_CHECK, self.sshkdf_key_check),
            (OSSL_PROV_PARAM_SSKDF_KEY_CHECK, self.sskdf_key_check),
            (OSSL_PROV_PARAM_X963KDF_KEY_CHECK, self.x963kdf_key_check),
            (OSSL_PROV_PARAM_X942KDF_KEY_CHECK, self.x942kdf_key_check),
            (
                OSSL_PROV_PARAM_PBKDF2_LOWER_BOUND_CHECK,
                self.pbkdf2_lower_bound_check,
            ),
            (
                OSSL_PROV_PARAM_ECDH_COFACTOR_CHECK,
                self.ecdh_cofactor_check,
            ),
        ]
    }
}

/// `check_non_pedantic_fips`.
fn check_non_pedantic_fips(pedantic: bool, name: &str) -> bool {
    if pedantic {
        eprintf!("Cannot specify -{name} after -pedantic\n");
        return false;
    }
    true
}

/// `do_mac`: the MAC of everything `input` holds; `None` on failure.
fn do_mac(ctx: &MacCtx, input: &Bio) -> Option<Vec<u8>> {
    let outsz = usize::try_from(EVP_MAX_MD_SIZE).unwrap_or(64);
    if !ctx.init() {
        return None;
    }
    // A MAC too long for the buffer skips the input; the final call then fails.
    if ctx.mac_size() <= outsz {
        let mut tmp = vec![0u8; BUFSIZE];
        loop {
            let i = input.read(&mut tmp);
            let Ok(n) = usize::try_from(i) else {
                return None;
            };
            if n == 0 {
                break;
            }
            if !ctx.update(tmp.get(..n).unwrap_or_default()) {
                return None;
            }
        }
    }
    let mut out = vec![0u8; outsz];
    let n = ctx.finish(&mut out)?;
    out.truncate(n);
    Some(out)
}

/// `OPENSSL_buf2hexstr`: uppercase hex pairs separated by `:`.
fn buf2hexstr(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `write_config_header`.
fn config_header(prov_name: &str, section: &str) -> String {
    format!(
        "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_section\n\n\
         [provider_section]\n{prov_name} = {section}\n\n"
    )
}

/// `write_config_fips_section`.
fn config_fips_section(
    section: &str,
    module_mac: &[u8],
    opts: &FipsOpts,
    install_mac: Option<&[u8]>,
) -> String {
    let mut t = format!("[{section}]\nactivate = 1\n");
    t.push_str(&format!(
        "{} = {VERSION_VAL}\n",
        s(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION)
    ));
    for (name, on) in opts.settings() {
        t.push_str(&format!("{} = {}\n", s(name), if on { "1" } else { "0" }));
    }
    t.push_str(&format!(
        "{} = {}\n",
        s(OSSL_PROV_FIPS_PARAM_MODULE_MAC),
        buf2hexstr(module_mac)
    ));
    if let Some(install_mac) = install_mac
        && !install_mac.is_empty()
        && !opts.self_test_onload
    {
        t.push_str(&format!(
            "{} = {}\n{} = {INSTALL_STATUS_VAL}\n",
            s(OSSL_PROV_FIPS_PARAM_INSTALL_MAC),
            buf2hexstr(install_mac),
            s(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS)
        ));
    }
    t
}

/// `generate_config_and_load`: the configuration in memory, loaded with its modules.
fn generate_config_and_load(
    prov_name: &str,
    section: &str,
    module_mac: &[u8],
    opts: &FipsOpts,
) -> Option<Conf> {
    let text =
        config_header(prov_name, section) + &config_fips_section(section, module_mac, opts, None);
    let mem = Bio::from_bytes(text.as_bytes())?;
    let conf = app_load_config_bio(&mem, None)?;
    if conf.modules_load(0) <= 0 {
        return None;
    }
    Some(conf)
}

/// `load_fips_prov_and_run_self_test`: whether it loaded, and whether the module is a FIPS
/// 140-2 one (version 3.0.x).
fn load_fips_prov_and_run_self_test(prov_name: &str, quiet: bool) -> Option<bool> {
    let Some(prov) = Provider::load(None, prov_name) else {
        eprintf!("Failed to load FIPS module\n");
        return None;
    };
    let vers = if !quiet {
        let keys = [
            s(OSSL_PROV_PARAM_NAME),
            s(OSSL_PROV_PARAM_VERSION),
            s(OSSL_PROV_PARAM_BUILDINFO),
        ];
        let Some(values) = prov.get_utf8_ptr_params(&keys) else {
            eprintf!("Failed to query FIPS module parameters\n");
            return None;
        };
        for (label, v) in ["name:", "version:", "build:"].iter().zip(&values) {
            if let Some(v) = v {
                eprintf!("\t{label:<10}\t{v}\n");
            }
        }
        values.get(1).cloned().flatten()
    } else {
        let Some(values) = prov.get_utf8_ptr_params(&[s(OSSL_PROV_PARAM_VERSION)]) else {
            eprintf!("Failed to query FIPS module parameters\n");
            return None;
        };
        values.first().cloned().flatten()
    };
    Some(vers.unwrap_or_default().starts_with("3.0."))
}

/// `verify_config`: whether the file's section holds the version and these MACs.
fn verify_config(infile: &str, section: &str, module_mac: &[u8], install_mac: &[u8]) -> bool {
    let Some(conf) = app_load_config(Some(infile)) else {
        return false;
    };
    let get = |name: &CStr| conf.get_string(Some(section), s(name));
    if get(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION).as_deref() != Some(VERSION_VAL) {
        eprintf!("version not found\n");
        return false;
    }
    let Some(m) = get(OSSL_PROV_FIPS_PARAM_MODULE_MAC) else {
        eprintf!("Module integrity MAC not found\n");
        return false;
    };
    if rustyssl_ossl::crypto::hexstr2buf(&m).as_deref() != Some(module_mac) {
        eprintf!("Module integrity mismatch\n");
        return false;
    }
    if !install_mac.is_empty() {
        if get(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS).as_deref() != Some(INSTALL_STATUS_VAL) {
            eprintf!("install status not found\n");
            return false;
        }
        let Some(m) = get(OSSL_PROV_FIPS_PARAM_INSTALL_MAC) else {
            eprintf!("Install indicator MAC not found\n");
            return false;
        };
        if rustyssl_ossl::crypto::hexstr2buf(&m).as_deref() != Some(install_mac) {
            eprintf!("Install indicator status mismatch\n");
            return false;
        }
    }
    true
}

/// How `run` ends: `cleanup` skips the failure message.
enum End {
    Done(i32),
    Cleanup(i32),
}

pub fn main(argv: &[String]) -> i32 {
    let mut verify = false;
    let mut quiet = false;
    let mut conf: Option<Conf> = None;
    let ret = match run(argv, &mut verify, &mut quiet, &mut conf) {
        End::Cleanup(r) => r,
        End::Done(r) => {
            if r == 1 {
                if !quiet {
                    let what = if verify { "VERIFY" } else { "INSTALL" };
                    eprintf!("{what} FAILED\n");
                }
                io::print_errors();
            }
            r
        }
    };
    // free_config_and_unload.
    if conf.take().is_some() {
        conf::modules_unload(true);
    }
    ret
}

fn run(argv: &[String], verify: &mut bool, quiet: &mut bool, conf: &mut Option<Conf>) -> End {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let opthelp = || {
        eprintf!("{prog}: Use -help for summary.\n");
        End::Cleanup(1)
    };
    let mut fips_opts = FipsOpts::DEFAULT;
    let (mut pedantic, mut set_selftest_onload_option) = (false, false);
    let (mut gotkey, mut gotdigest) = (false, false);
    let mut self_test_log = true;
    let mut corrupt_desc: Option<String> = None;
    let mut corrupt_type: Option<String> = None;
    let mut section_name = "fips_sect".to_owned();
    let mut mac_name = "HMAC".to_owned();
    let mut prov_name = "fips".to_owned();
    let (mut in_fname, mut out_fname) = (None::<String>, None::<String>);
    let (mut module_fname, mut parent_config) = (None::<String>, None::<String>);
    let mut opts: Vec<String> = Vec::new();
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return opthelp(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return End::Done(0);
            }
            Opt::IN => in_fname = Some(p.arg().to_owned()),
            Opt::OUT => out_fname = Some(p.arg().to_owned()),
            Opt::PEDANTIC => {
                fips_opts = FipsOpts::PEDANTIC;
                pedantic = true;
            }
            Opt::NO_CONDITIONAL_ERRORS => {
                if !check_non_pedantic_fips(pedantic, "no_conditional_errors") {
                    return End::Done(1);
                }
                fips_opts.conditional_errors = false;
            }
            Opt::NO_SECURITY_CHECKS => {
                if !check_non_pedantic_fips(pedantic, "no_security_checks") {
                    return End::Done(1);
                }
                fips_opts.security_checks = false;
            }
            Opt::HMAC_KEY_CHECK => fips_opts.hmac_key_check = true,
            Opt::KMAC_KEY_CHECK => fips_opts.kmac_key_check = true,
            Opt::TLS_PRF_EMS_CHECK => fips_opts.tls_prf_ems_check = true,
            Opt::NO_SHORT_MAC => fips_opts.no_short_mac = true,
            Opt::DISALLOW_DRGB_TRUNC_DIGEST => fips_opts.drgb_no_trunc_dgst = true,
            Opt::SIGNATURE_DIGEST_CHECK => fips_opts.signature_digest_check = true,
            Opt::HKDF_DIGEST_CHECK => fips_opts.hkdf_digest_check = true,
            Opt::TLS13_KDF_DIGEST_CHECK => fips_opts.tls13_kdf_digest_check = true,
            Opt::TLS1_PRF_DIGEST_CHECK => fips_opts.tls1_prf_digest_check = true,
            Opt::SSHKDF_DIGEST_CHECK => fips_opts.sshkdf_digest_check = true,
            Opt::SSKDF_DIGEST_CHECK => fips_opts.sskdf_digest_check = true,
            Opt::X963KDF_DIGEST_CHECK => fips_opts.x963kdf_digest_check = true,
            Opt::DISALLOW_DSA_SIGN => fips_opts.dsa_sign_disabled = true,
            Opt::DISALLOW_TDES_ENCRYPT => fips_opts.tdes_encrypt_disabled = true,
            Opt::RSA_PSS_SALTLEN_CHECK => fips_opts.rsa_pss_saltlen_check = true,
            Opt::DISALLOW_SIGNATURE_X931_PADDING => fips_opts.sign_x931_padding_disabled = true,
            Opt::DISALLOW_PKCS15_PADDING => fips_opts.rsa_pkcs15_padding_disabled = true,
            Opt::HKDF_KEY_CHECK => fips_opts.hkdf_key_check = true,
            Opt::KBKDF_KEY_CHECK => fips_opts.kbkdf_key_check = true,
            Opt::TLS13_KDF_KEY_CHECK => fips_opts.tls13_kdf_key_check = true,
            Opt::TLS1_PRF_KEY_CHECK => fips_opts.tls1_prf_key_check = true,
            Opt::SSHKDF_KEY_CHECK => fips_opts.sshkdf_key_check = true,
            Opt::SSKDF_KEY_CHECK => fips_opts.sskdf_key_check = true,
            Opt::X963KDF_KEY_CHECK => fips_opts.x963kdf_key_check = true,
            Opt::X942KDF_KEY_CHECK => fips_opts.x942kdf_key_check = true,
            Opt::NO_PBKDF2_LOWER_BOUND_CHECK => {
                if !check_non_pedantic_fips(pedantic, "no_pbkdf2_lower_bound_check") {
                    return End::Done(1);
                }
                fips_opts.pbkdf2_lower_bound_check = false;
            }
            Opt::ECDH_COFACTOR_CHECK => fips_opts.ecdh_cofactor_check = true,
            Opt::QUIET => {
                *quiet = true;
                self_test_log = false;
            }
            Opt::NO_LOG => self_test_log = false,
            Opt::CORRUPT_DESC => corrupt_desc = Some(p.arg().to_owned()),
            Opt::CORRUPT_TYPE => corrupt_type = Some(p.arg().to_owned()),
            Opt::PROV_NAME => prov_name = p.arg().to_owned(),
            Opt::MODULE => module_fname = Some(p.arg().to_owned()),
            Opt::SECTION_NAME => section_name = p.arg().to_owned(),
            Opt::MAC_NAME => mac_name = p.arg().to_owned(),
            Opt::CONFIG => parent_config = Some(p.arg().to_owned()),
            Opt::MACOPT => {
                let a = p.arg().to_owned();
                if a.starts_with("hexkey:") {
                    gotkey = true;
                } else if a.starts_with("digest:") {
                    gotdigest = true;
                }
                opts.push(a);
            }
            Opt::VERIFY => *verify = true,
            Opt::SELF_TEST_ONLOAD => {
                set_selftest_onload_option = true;
                fips_opts.self_test_onload = true;
            }
            Opt::SELF_TEST_ONINSTALL => {
                if !check_non_pedantic_fips(pedantic, "self_test_oninstall") {
                    return End::Done(1);
                }
                set_selftest_onload_option = true;
                fips_opts.self_test_onload = false;
            }
        }
    }

    // No extra arguments.
    if !p.check_rest_arg(None) {
        return opthelp();
    }
    if *verify && in_fname.is_none() {
        eprintf!("Missing -in option for -verify\n");
        return opthelp();
    }

    if let Some(parent) = &parent_config {
        // Whether a parent configuration can load the module.
        if provider::load_config(None, parent) {
            let r = if provider::available(None, &prov_name) {
                0
            } else {
                1
            };
            if !*quiet {
                let what = if r == 0 { "available" } else { "not available" };
                eprintf!("FIPS provider is {what}\n");
            }
            return End::Done(r);
        }
        return End::Done(1);
    }
    let Some(module_fname) = module_fname else {
        return opthelp();
    };

    // The module's directory is where providers are loaded from.
    let tail = opt::path_end(&module_fname);
    let dir = module_fname
        .get(..module_fname.len() - tail.len())
        .unwrap_or_default();
    if !provider::set_default_search_path(None, Some(dir)) {
        return End::Done(1);
    }

    if self_test_log || corrupt_desc.is_some() || corrupt_type.is_some() {
        provider::set_self_test_callback(move |phase, desc, kind| {
            self_test_event(
                self_test_log,
                corrupt_desc.as_deref(),
                corrupt_type.as_deref(),
                phase,
                desc,
                kind,
            )
        });
    }

    // The default FIPS HMAC digest and key unless given.
    if !gotdigest {
        opts.push("digest:SHA256".to_owned());
    }
    if !gotkey {
        opts.push(format!("hexkey:{}", s(FIPS_KEY_STRING)));
    }

    let Some(module_bio) = bio_open_default(Some(&module_fname), 'r', format::BINARY) else {
        eprintf!("Failed to open module file\n");
        return End::Done(1);
    };

    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(mac) = Mac::fetch(lc.as_deref(), &mac_name, pq.as_deref()) else {
        eprintf!("Unable to get MAC of type {mac_name}\n");
        return End::Done(1);
    };
    let Some(ctx) = MacCtx::new(&mac) else {
        eprintf!("Unable to create MAC CTX for module check\n");
        return End::Done(1);
    };
    let params = match Params::from_text(mac.settable_ctx_params(), &opts) {
        Ok(p) => p,
        Err(e) => {
            let what = if e.found { "error" } else { "unknown" };
            eprintf!("Parameter {what} '{}'\n", e.opt);
            io::print_errors();
            return End::Done(1);
        }
    };
    if !ctx.set_params(&params) {
        eprintf!("MAC parameter error\n");
        io::print_errors();
        return End::Done(1);
    }
    drop(params);
    let Some(ctx2) = ctx.dup() else {
        eprintf!("Unable to create MAC CTX for install indicator\n");
        return End::Done(1);
    };

    let Some(module_mac) = do_mac(&ctx, &module_bio) else {
        return End::Done(1);
    };
    // The MAC of the indicator status, which may not be used.
    let Some(mem_bio) = Bio::new_mem_buf(INSTALL_STATUS_VAL.as_bytes()) else {
        eprintf!("Unable to create memory BIO\n");
        return End::Done(1);
    };
    let Some(mut install_mac) = do_mac(&ctx2, &mem_bio) else {
        return End::Done(1);
    };

    if *verify {
        if fips_opts.self_test_onload {
            install_mac.clear();
        }
        let in_fname = in_fname.unwrap_or_default();
        if !verify_config(&in_fname, &section_name, &module_mac, &install_mac) {
            return End::Done(1);
        }
        if !*quiet {
            eprintf!("VERIFY PASSED\n");
        }
    } else {
        *conf = generate_config_and_load(&prov_name, &section_name, &module_mac, &fips_opts);
        if conf.is_none() {
            return End::Done(1);
        }
        let Some(is_fips_140_2_prov) = load_fips_prov_and_run_self_test(&prov_name, *quiet) else {
            return End::Done(1);
        };
        // A 3.0.x (FIPS 140-2) module gets the indicator status unless told otherwise.
        if !set_selftest_onload_option && is_fips_140_2_prov {
            fips_opts.self_test_onload = false;
        }
        let fout = match &out_fname {
            None => dup_bio_out(format::TEXT),
            Some(f) => bio_open_default(Some(f), 'w', format::TEXT),
        };
        let Some(fout) = fout else {
            eprintf!("Failed to open file\n");
            return End::Done(1);
        };
        let text = config_fips_section(&section_name, &module_mac, &fips_opts, Some(&install_mac));
        if fout.write_all(text.as_bytes()).is_err() {
            return End::Done(1);
        }
        if !*quiet {
            eprintf!("INSTALL PASSED\n");
        }
    }
    End::Done(0)
}

/// `self_test_events`: logs each self test, and corrupts the one named by description and
/// type (returning false in its corrupt phase).
fn self_test_event(
    log: bool,
    corrupt_desc: Option<&str>,
    corrupt_type: Option<&str>,
    phase: &str,
    desc: &str,
    kind: &str,
) -> bool {
    if log {
        if phase == s(OSSL_SELF_TEST_PHASE_START) {
            eprintf!("{desc} : ({kind}) : ");
        } else if phase == s(OSSL_SELF_TEST_PHASE_PASS) || phase == s(OSSL_SELF_TEST_PHASE_FAIL) {
            eprintf!("{phase}\n");
        }
    }
    if phase == s(OSSL_SELF_TEST_PHASE_CORRUPT)
        && (corrupt_desc.is_some() || corrupt_type.is_some())
    {
        if corrupt_desc.is_some_and(|d| d != desc) || corrupt_type.is_some_and(|t| t != kind) {
            return true;
        }
        eprintf!("{phase} ");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex() {
        assert_eq!(buf2hexstr(&[]), "");
        assert_eq!(buf2hexstr(&[0x6d, 0x0a, 0xff]), "6D:0A:FF");
    }

    #[test]
    fn section() {
        let t = config_fips_section("s", &[1, 2], &FipsOpts::DEFAULT, Some(&[3]));
        assert!(t.starts_with("[s]\nactivate = 1\ninstall-version = 1\nconditional-errors = 1\n"));
        assert!(t.ends_with("ecdh-cofactor-check = 0\nmodule-mac = 01:02\n"));
        let mut o = FipsOpts::DEFAULT;
        o.self_test_onload = false;
        let t = config_fips_section("s", &[1], &o, Some(&[3]));
        assert!(t.ends_with(
            "module-mac = 01\ninstall-mac = 03\ninstall-status = INSTALL_SELF_TEST_KATS_RUN\n"
        ));
        assert_eq!(FipsOpts::PEDANTIC.settings().len(), 29);
    }

    /// `self_test_events`, which no module here calls: logging, and corrupting the test named.
    #[test]
    fn self_test_events() {
        let (ok, text) = io::capture_err(|| {
            self_test_event(true, None, None, "Start", "SHA2", "KAT_Digest")
                && self_test_event(true, None, None, "Pass", "SHA2", "KAT_Digest")
                && self_test_event(true, None, None, "Corrupt", "SHA2", "KAT_Digest")
        });
        assert!(ok);
        assert_eq!(text, b"SHA2 : (KAT_Digest) : Pass\n");
        let (ok, text) = io::capture_err(|| {
            self_test_event(false, Some("SHA2"), None, "Corrupt", "SHA2", "KAT_Digest")
        });
        assert!(!ok);
        assert_eq!(text, b"Corrupt ");
        let (ok, text) = io::capture_err(|| {
            self_test_event(
                false,
                Some("SHA2"),
                Some("other"),
                "Corrupt",
                "SHA2",
                "KAT_Digest",
            )
        });
        assert!(ok);
        assert!(text.is_empty());
        let (ok, text) = io::capture_err(|| {
            self_test_event(true, None, Some("KAT_Digest"), "Fail", "SHA2", "KAT_Digest")
        });
        assert!(ok);
        assert_eq!(text, b"Fail\n");
    }
}
