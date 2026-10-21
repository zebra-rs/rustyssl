//! The TLS commands' callbacks and shared logic: a port of `apps/lib/s_cb.c` (`s_client`,
//! `s_server`, `s_time`), with `apps.c`'s TLS helpers (`ctx_set_verify_locations`,
//! `ctx_set_ctlog_list_file`, `next_protos_parse`, `wait_for_async`, `policies_print`) and
//! the SRP setup of `apps/lib/tlssrp_depr.c`.

// The C API's constants keep their names (`NID_id_GostR3410_2001`, ...).
#![allow(non_upper_case_globals)]

use std::cell::{Cell, RefCell};

use rustyssl_ossl::abi::*;
use rustyssl_ossl::srp as srpx;
use rustyssl_ossl::ssl::{self, ConfCtx, CtxRef, SslRef};
use rustyssl_ossl::ssl_cb::{BioCbArgs, SecArgs, SecOther, StoreCtxRef};
use rustyssl_ossl::x509::{self, Cert, CertStack, CrlStack, Store};
use rustyssl_ossl::{Bio, pkey::Pkey};

use super::apps::{self, get_nameopt};
use super::io;
use super::opt::{self, eprintf, format};
use crate::generated::options::X;

/// `VERIFY_CB_ARGS verify_args`.
#[derive(Clone, Copy)]
pub struct VerifyArgs {
    pub depth: i32,
    pub quiet: bool,
    pub error: i32,
    pub return_error: bool,
}

thread_local! {
    static VERIFY_ARGS: Cell<VerifyArgs> = const {
        Cell::new(VerifyArgs { depth: -1, quiet: false, error: X509_V_OK, return_error: false })
    };
    static COOKIE_SECRET: RefCell<Option<[u8; COOKIE_SECRET_LENGTH]>> = const { RefCell::new(None) };
    static BIO_KEYLOG: RefCell<Option<Bio>> = const { RefCell::new(None) };
    static EXCERT: RefCell<Vec<Excert>> = const { RefCell::new(Vec::new()) };
    static SEC_VERBOSE: Cell<i32> = const { Cell::new(0) };
}

const COOKIE_SECRET_LENGTH: usize = 16;

/// `verify_args`.
pub fn verify_args() -> VerifyArgs {
    VERIFY_ARGS.with(Cell::get)
}

/// Changes `verify_args`.
pub fn set_verify_args(f: impl FnOnce(&mut VerifyArgs)) {
    VERIFY_ARGS.with(|v| {
        let mut a = v.get();
        f(&mut a);
        v.set(a);
    });
}

fn bio_err() -> Option<&'static Bio> {
    io::bio_err()
}

/// Writes to `bio_err`.
fn eputs(s: &str) {
    if let Some(b) = bio_err() {
        let _ = b.write_all(s.as_bytes());
    }
}

fn puts(b: &Bio, s: &str) {
    let _ = b.write_all(s.as_bytes());
}

fn lookup<'a>(val: i32, list: &[(&'a str, i32)], def: Option<&'a str>) -> Option<&'a str> {
    list.iter()
        .find(|(_, v)| *v == val)
        .map(|(n, _)| *n)
        .or(def)
}

fn name_print(b: &Bio, nm: x509::NameRef<'_>) {
    x509::name_print_ex(b, nm, 0, get_nameopt());
}

/// `verify_callback`.
pub fn verify_callback(ok: i32, ctx: StoreCtxRef<'_>) -> i32 {
    let mut ok = ok;
    let err_cert = ctx.current_cert();
    let errn = ctx.error();
    let depth = ctx.error_depth();
    let args = verify_args();
    let Some(be) = bio_err() else { return ok };
    if !args.quiet || ok == 0 {
        puts(be, &format!("depth={depth} "));
        match &err_cert {
            Some(c) => {
                name_print(be, c.subject_name());
                puts(be, "\n");
            }
            None => puts(be, "<no cert>\n"),
        }
    }
    if ok == 0 {
        puts(
            be,
            &format!(
                "verify error:num={errn}:{}\n",
                ssl::verify_cert_error_string(errn.into())
            ),
        );
        if args.depth < 0 || args.depth >= depth {
            if !args.return_error {
                ok = 1;
            }
            set_verify_args(|a| a.error = errn);
        } else {
            ok = 0;
            set_verify_args(|a| a.error = X509_V_ERR_CERT_CHAIN_TOO_LONG);
        }
    }
    match errn {
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT => {
            if let Some(c) = &err_cert {
                puts(be, "issuer= ");
                name_print(be, c.issuer_name());
                puts(be, "\n");
            }
        }
        X509_V_ERR_CERT_NOT_YET_VALID | X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD => {
            if let Some(c) = &err_cert {
                puts(be, "notBefore=");
                ssl::print_cert_time(be, c, false);
                puts(be, "\n");
            }
        }
        X509_V_ERR_CERT_HAS_EXPIRED | X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD => {
            if let Some(c) = &err_cert {
                puts(be, "notAfter=");
                ssl::print_cert_time(be, c, true);
                puts(be, "\n");
            }
        }
        X509_V_ERR_NO_EXPLICIT_POLICY => {
            if !args.quiet {
                policies_print(ctx);
            }
        }
        X509_V_ERR_OCSP_NO_RESPONSE if !args.quiet => {
            puts(be, "no OCSP response(s) for certificate(s) found.\n");
        }
        _ => {}
    }
    if errn == X509_V_OK && ok == 2 && !args.quiet {
        policies_print(ctx);
    }
    if ok != 0 && !args.quiet {
        puts(be, &format!("verify return:{ok}\n"));
    }
    ok
}

/// `policies_print` of `apps.c`.
pub fn policies_print(ctx: StoreCtxRef<'_>) {
    let Some(be) = bio_err() else { return };
    let explicit = if ctx.explicit_policy() {
        "True"
    } else {
        "False"
    };
    puts(be, &format!("Require explicit Policy: {explicit}\n"));
    for (name, user) in [("Authority", false), ("User", true)] {
        puts(be, &format!("{name} Policies:"));
        // The stack is printed after the newline, or <empty> when there is none.
        let (printed, text) = {
            let mem = Bio::new_mem();
            match &mem {
                Some(m) => (ctx.print_policy_nodes(m, user, 2), m.read_to_end()),
                None => (false, Vec::new()),
            }
        };
        if printed {
            puts(be, "\n");
            let _ = be.write_all(&text);
        } else {
            puts(be, " <empty>\n");
        }
    }
}

/// `set_cert_stuff(ctx, cert_file, key_file)`.
pub fn set_cert_stuff(ctx: CtxRef<'_>, cert_file: Option<&str>, key_file: Option<&str>) -> bool {
    let Some(cert_file) = cert_file else {
        return true;
    };
    if ctx.use_certificate_file_pem(cert_file) <= 0 {
        eprintf!("unable to get certificate from '{cert_file}'\n");
        io::print_errors();
        return false;
    }
    let key_file = key_file.unwrap_or(cert_file);
    if ctx.use_private_key_file_pem(key_file) <= 0 {
        eprintf!("unable to get private key from '{key_file}'\n");
        io::print_errors();
        return false;
    }
    if !ctx.check_private_key() {
        eprintf!("Private key does not match the certificate public key\n");
        return false;
    }
    true
}

/// `set_cert_key_stuff(ctx, cert, key, chain, build_chain)`.
pub fn set_cert_key_stuff(
    ctx: CtxRef<'_>,
    cert: Option<&Cert>,
    key: Option<&Pkey>,
    chain: Option<&CertStack>,
    build_chain: bool,
) -> bool {
    let chflags = if chain.is_some() {
        SSL_BUILD_CHAIN_FLAG_CHECK
    } else {
        0
    };
    let Some(cert) = cert else {
        return true;
    };
    if ctx.use_certificate(cert) <= 0 {
        eprintf!("error setting certificate\n");
        io::print_errors();
        return false;
    }
    if key.is_none_or(|k| ctx.use_private_key(k) <= 0) {
        eprintf!("error setting private key\n");
        io::print_errors();
        return false;
    }
    if !ctx.check_private_key() {
        eprintf!("Private key does not match the certificate public key\n");
        return false;
    }
    if let Some(ch) = chain
        && !ctx.set1_chain(ch)
    {
        eprintf!("error setting certificate chain\n");
        io::print_errors();
        return false;
    }
    if build_chain && !ctx.build_cert_chain(chflags.into()) {
        eprintf!("error building certificate chain\n");
        io::print_errors();
        return false;
    }
    true
}

const CERT_TYPE_LIST: [(&str, i32); 9] = [
    ("RSA sign", TLS_CT_RSA_SIGN),
    ("DSA sign", TLS_CT_DSS_SIGN),
    ("RSA fixed DH", TLS_CT_RSA_FIXED_DH),
    ("DSS fixed DH", TLS_CT_DSS_FIXED_DH),
    ("ECDSA sign", TLS_CT_ECDSA_SIGN),
    ("RSA fixed ECDH", TLS_CT_RSA_FIXED_ECDH),
    ("ECDSA fixed ECDH", TLS_CT_ECDSA_FIXED_ECDH),
    ("GOST01 Sign", TLS_CT_GOST01_SIGN),
    ("GOST12 Sign", TLS_CT_GOST12_IANA_SIGN),
];

fn ssl_print_client_cert_types(b: &Bio, s: SslRef<'_>) {
    let types = s.certificate_types();
    if types.is_empty() {
        return;
    }
    let mut out = String::from("Client Certificate Types: ");
    for (i, &t) in types.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match lookup(i32::from(t), &CERT_TYPE_LIST, None) {
            Some(n) => out.push_str(n),
            None => out.push_str(&format!("UNKNOWN ({t}),")),
        }
    }
    out.push('\n');
    puts(b, &out);
}

fn get_sigtype(nid: i32) -> Option<String> {
    Some(
        match nid {
            EVP_PKEY_RSA => "RSA",
            EVP_PKEY_RSA_PSS => "RSA-PSS",
            EVP_PKEY_DSA => "DSA",
            EVP_PKEY_EC => "ECDSA",
            NID_ED25519 => "ed25519",
            NID_ED448 => "ed448",
            NID_id_GostR3410_2001 => "gost2001",
            NID_id_GostR3410_2012_256 => "gost2012_256",
            NID_id_GostR3410_2012_512 => "gost2012_512",
            // Try to output a provider-registered signature algorithm's name.
            _ => return ssl::nid2sn(nid),
        }
        .to_owned(),
    )
}

fn do_print_sigalgs(out: &Bio, s: SslRef<'_>, shared: bool) {
    let client = !s.is_server();
    let nsig = s.sigalgs(-1, shared).0;
    if nsig == 0 {
        return;
    }
    let mut text = String::new();
    if shared {
        text.push_str("Shared ");
    }
    if client {
        text.push_str("Requested ");
    }
    text.push_str("Signature Algorithms: ");
    for i in 0..nsig {
        let (_, sign_nid, hash_nid, rsign, rhash) = s.sigalgs(i, shared);
        if i > 0 {
            text.push(':');
        }
        let special = match u16::from(rsign) | (u16::from(rhash) << 8) {
            0x0809 => Some("rsa_pss_pss_sha256"),
            0x080a => Some("rsa_pss_pss_sha384"),
            0x080b => Some("rsa_pss_pss_sha512"),
            0x081a => Some("ecdsa_brainpoolP256r1_sha256"),
            0x081b => Some("ecdsa_brainpoolP384r1_sha384"),
            0x081c => Some("ecdsa_brainpoolP512r1_sha512"),
            _ => None,
        };
        if let Some(n) = special {
            text.push_str(n);
            continue;
        }
        let sstr = get_sigtype(sign_nid);
        match &sstr {
            Some(n) => text.push_str(n),
            None => text.push_str(&format!("0x{rsign:02X}")),
        }
        if hash_nid != NID_undef {
            text.push_str(&format!("+{}", sn(hash_nid)));
        } else if sstr.is_none() {
            text.push_str(&format!("+0x{rhash:02X}"));
        }
    }
    text.push('\n');
    puts(out, &text);
}

/// `OBJ_nid2sn`, as `%s` prints it.
fn sn(nid: i32) -> String {
    ssl::nid2sn(nid).unwrap_or_else(|| "<NULL>".to_owned())
}

/// `ssl_print_sigalgs`.
pub fn ssl_print_sigalgs(out: &Bio, s: SslRef<'_>) {
    if !s.is_server() {
        ssl_print_client_cert_types(out, s);
    }
    do_print_sigalgs(out, s, false);
    do_print_sigalgs(out, s, true);
    if let Some(nid) = s.peer_signature_nid()
        && nid != NID_undef
    {
        puts(out, &format!("Peer signing digest: {}\n", sn(nid)));
    }
    if let Some(name) = s.peer_signature_name() {
        puts(out, &format!("Peer signature type: {name}\n"));
    } else if let Some(nid) = s.peer_signature_type_nid() {
        let t = get_sigtype(nid).unwrap_or_else(|| "<NULL>".to_owned());
        puts(out, &format!("Peer signature type: {t}\n"));
    }
}

/// `ssl_print_point_formats`.
pub fn ssl_print_point_formats(out: &Bio, s: SslRef<'_>) {
    let formats = s.ec_point_formats();
    if formats.is_empty() {
        return;
    }
    let mut text = String::from("Supported Elliptic Curve Point Formats: ");
    for (i, &f) in formats.iter().enumerate() {
        if i > 0 {
            text.push(':');
        }
        match i32::from(f) {
            TLSEXT_ECPOINTFORMAT_uncompressed => text.push_str("uncompressed"),
            TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime => {
                text.push_str("ansiX962_compressed_prime");
            }
            TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 => {
                text.push_str("ansiX962_compressed_char2");
            }
            _ => text.push_str(&format!("unknown({f})")),
        }
    }
    text.push('\n');
    puts(out, &text);
}

fn group_name(s: SslRef<'_>, nid: i32) -> String {
    s.group_to_name(nid).unwrap_or_else(|| "<NULL>".to_owned())
}

/// `ssl_print_groups(out, s, noshared)`.
pub fn ssl_print_groups(out: &Bio, s: SslRef<'_>, noshared: bool) {
    let groups = s.groups();
    if groups.is_empty() {
        return;
    }
    let mut text = String::from("Supported groups: ");
    for (i, &nid) in groups.iter().enumerate() {
        if i > 0 {
            text.push(':');
        }
        text.push_str(&group_name(s, nid));
    }
    if noshared {
        text.push('\n');
        puts(out, &text);
        return;
    }
    text.push_str("\nShared groups: ");
    let n = s.shared_group(-1);
    for i in 0..n.max(0) {
        if i > 0 {
            text.push(':');
        }
        let nid = i32::try_from(s.shared_group(i)).unwrap_or(0);
        text.push_str(&group_name(s, nid));
    }
    if n == 0 {
        text.push_str("NONE");
    }
    text.push('\n');
    puts(out, &text);
}

/// `ssl_print_tmp_key`.
pub fn ssl_print_tmp_key(out: &Bio, s: SslRef<'_>) {
    let Some(key) = s.peer_tmp_key() else {
        if s.version() == TLS1_3_VERSION {
            let g = group_name(s, s.negotiated_group());
            puts(out, &format!("Negotiated TLS1.3 group: {g}\n"));
        }
        return;
    };
    let mut text = String::from("Peer Temp Key: ");
    match key.id() {
        EVP_PKEY_RSA => text.push_str(&format!("RSA, {} bits\n", key.bits())),
        EVP_PKEY_KEYMGMT => {
            let name = key.type_name().unwrap_or_else(|| "?".to_owned());
            text.push_str(&format!("{name}\n"));
        }
        EVP_PKEY_DH => text.push_str(&format!("DH, {} bits\n", key.bits())),
        EVP_PKEY_EC => {
            let name = key.group_name_param().unwrap_or_else(|| "?".to_owned());
            text.push_str(&format!("ECDH, {name}, {} bits\n", key.bits()));
        }
        id => text.push_str(&format!("{}, {} bits\n", sn(id), key.bits())),
    }
    puts(out, &text);
}

/// `bio_dump_callback`: the reads and writes of the `BIO`, dumped to the `BIO` set as its
/// callback argument.
pub fn bio_dump_callback(a: &BioCbArgs<'_>) -> core::ffi::c_long {
    let ret = core::ffi::c_long::from(a.ret);
    let Some(out) = a.bio.callback_arg_bio() else {
        return ret;
    };
    bio_dump(&out, a);
    ret
}

/// The body of `bio_dump_callback`, writing to `out`.
pub fn bio_dump(out: &Bio, a: &BioCbArgs<'_>) {
    let (bio, argp, len) = (a.bio_addr(), a.argp_addr(), a.len);
    let rw = |verb: &str| match a.processed() {
        Some(p) if a.ret > 0 => {
            puts(
                out,
                &format!("{verb} 0x{bio:x} [0x{argp:x}] ({len} bytes => {p} (0x{p:X}))\n"),
            );
            ssl::bio_dump(out, a.data());
        }
        _ => puts(
            out,
            &format!("{verb} 0x{bio:x} [0x{argp:x}] ({len} bytes => {})\n", a.ret),
        ),
    };
    let mm = |verb: &str| {
        let (msgs, num, first) = a.mmsgs();
        if a.ret > 0 {
            for (addr, d) in msgs {
                let n = d.len();
                puts(
                    out,
                    &format!("{verb} 0x{bio:x} [0x{addr:x}] ({n} bytes => {n} (0x{n:X}))\n"),
                );
                if i32::try_from(n).is_ok() {
                    ssl::bio_dump(out, d);
                }
            }
        } else if num > 0
            && let Some((addr, n)) = first
        {
            puts(
                out,
                &format!("{verb} 0x{bio:x} [0x{addr:x}] ({n} bytes => {})\n", a.ret),
            );
        }
    };
    match a.cmd {
        c if c == BIO_CB_READ | BIO_CB_RETURN => rw("read from"),
        c if c == BIO_CB_WRITE | BIO_CB_RETURN => rw("write to"),
        c if c == BIO_CB_RECVMMSG | BIO_CB_RETURN => mm("read from"),
        c if c == BIO_CB_SENDMMSG | BIO_CB_RETURN => mm("write to"),
        _ => {}
    }
}

/// `apps_ssl_info_callback`.
pub fn apps_ssl_info_callback(s: SslRef<'_>, where_: i32, ret: i32) {
    let w = where_ & !SSL_ST_MASK;
    let mut str_ = if w & SSL_ST_CONNECT != 0 {
        "SSL_connect"
    } else if w & SSL_ST_ACCEPT != 0 {
        "SSL_accept"
    } else {
        "undefined"
    };
    if where_ & SSL_CB_LOOP != 0 {
        eputs(&format!("{str_}:{}\n", s.state_string_long()));
    } else if where_ & SSL_CB_ALERT != 0 {
        str_ = if where_ & SSL_CB_READ != 0 {
            "read"
        } else {
            "write"
        };
        eputs(&format!(
            "SSL3 alert {str_}:{}:{}\n",
            ssl::alert_type_string_long(ret),
            ssl::alert_desc_string_long(ret)
        ));
    } else if where_ & SSL_CB_EXIT != 0 {
        if ret == 0 {
            eputs(&format!("{str_}:failed in {}\n", s.state_string_long()));
        } else if ret < 0 {
            eputs(&format!("{str_}:error in {}\n", s.state_string_long()));
        }
    }
}

const SSL_VERSIONS: [(&str, i32); 7] = [
    ("SSL 3.0", SSL3_VERSION),
    ("TLS 1.0", TLS1_VERSION),
    ("TLS 1.1", TLS1_1_VERSION),
    ("TLS 1.2", TLS1_2_VERSION),
    ("TLS 1.3", TLS1_3_VERSION),
    ("DTLS 1.0", DTLS1_VERSION),
    ("DTLS 1.0 (bad)", DTLS1_BAD_VER),
];

const ALERT_TYPES: [(&str, i32); 31] = [
    (" close_notify", 0),
    (" end_of_early_data", 1),
    (" unexpected_message", 10),
    (" bad_record_mac", 20),
    (" decryption_failed", 21),
    (" record_overflow", 22),
    (" decompression_failure", 30),
    (" handshake_failure", 40),
    (" bad_certificate", 42),
    (" unsupported_certificate", 43),
    (" certificate_revoked", 44),
    (" certificate_expired", 45),
    (" certificate_unknown", 46),
    (" illegal_parameter", 47),
    (" unknown_ca", 48),
    (" access_denied", 49),
    (" decode_error", 50),
    (" decrypt_error", 51),
    (" export_restriction", 60),
    (" protocol_version", 70),
    (" insufficient_security", 71),
    (" internal_error", 80),
    (" inappropriate_fallback", 86),
    (" user_canceled", 90),
    (" no_renegotiation", 100),
    (" missing_extension", 109),
    (" unsupported_extension", 110),
    (" certificate_unobtainable", 111),
    (" unrecognized_name", 112),
    (" bad_certificate_status_response", 113),
    (" bad_certificate_hash_value", 114),
];

const ALERT_TYPES2: [(&str, i32); 2] = [
    (" unknown_psk_identity", 115),
    (" certificate_required", 116),
];

const HANDSHAKES: [(&str, i32); 21] = [
    (", HelloRequest", SSL3_MT_HELLO_REQUEST),
    (", ClientHello", SSL3_MT_CLIENT_HELLO),
    (", ServerHello", SSL3_MT_SERVER_HELLO),
    (", HelloVerifyRequest", DTLS1_MT_HELLO_VERIFY_REQUEST),
    (", NewSessionTicket", SSL3_MT_NEWSESSION_TICKET),
    (", EndOfEarlyData", SSL3_MT_END_OF_EARLY_DATA),
    (", EncryptedExtensions", SSL3_MT_ENCRYPTED_EXTENSIONS),
    (", Certificate", SSL3_MT_CERTIFICATE),
    (", ServerKeyExchange", SSL3_MT_SERVER_KEY_EXCHANGE),
    (", CertificateRequest", SSL3_MT_CERTIFICATE_REQUEST),
    (", ServerHelloDone", SSL3_MT_SERVER_DONE),
    (", CertificateVerify", SSL3_MT_CERTIFICATE_VERIFY),
    (", ClientKeyExchange", SSL3_MT_CLIENT_KEY_EXCHANGE),
    (", Finished", SSL3_MT_FINISHED),
    (", CertificateUrl", SSL3_MT_CERTIFICATE_URL),
    (", CertificateStatus", SSL3_MT_CERTIFICATE_STATUS),
    (", SupplementalData", SSL3_MT_SUPPLEMENTAL_DATA),
    (", KeyUpdate", SSL3_MT_KEY_UPDATE),
    (", CompressedCertificate", SSL3_MT_COMPRESSED_CERTIFICATE),
    (", NextProto", SSL3_MT_NEXT_PROTO),
    (", MessageHash", SSL3_MT_MESSAGE_HASH),
];

/// `msg_cb`.
pub fn msg_cb(
    write_p: i32,
    version: i32,
    content_type: i32,
    buf: &[u8],
    _ssl: SslRef<'_>,
    arg: Option<ssl::BioRef<'_>>,
) {
    let Some(bio) = arg else { return };
    let str_write_p = if write_p != 0 { ">>>" } else { "<<<" };
    let len = buf.len();
    let (mut str_content_type, mut str_details1, mut str_details2) = (String::new(), "", "");
    let known = [
        SSL3_VERSION,
        TLS1_VERSION,
        TLS1_1_VERSION,
        TLS1_2_VERSION,
        TLS1_3_VERSION,
        DTLS1_VERSION,
        DTLS1_BAD_VER,
    ];
    let str_version = if known.contains(&version) {
        match content_type {
            SSL3_RT_CHANGE_CIPHER_SPEC => str_content_type = ", ChangeCipherSpec".to_owned(),
            SSL3_RT_ALERT => {
                str_content_type = ", Alert".to_owned();
                str_details1 = ", ???";
                if let [level, desc] = buf {
                    match level {
                        1 => str_details1 = ", warning",
                        2 => str_details1 = ", fatal",
                        _ => {}
                    }
                    let d = i32::from(*desc);
                    str_details2 = lookup(d, &ALERT_TYPES, None)
                        .or_else(|| lookup(d, &ALERT_TYPES2, None))
                        .unwrap_or(" ???");
                }
            }
            SSL3_RT_HANDSHAKE => {
                str_content_type = ", Handshake".to_owned();
                str_details1 = "???";
                if let Some(&t) = buf.first() {
                    str_details1 = lookup(i32::from(t), &HANDSHAKES, Some("???")).unwrap_or("???");
                }
            }
            SSL3_RT_APPLICATION_DATA => str_content_type = ", ApplicationData".to_owned(),
            SSL3_RT_HEADER => str_content_type = ", RecordHeader".to_owned(),
            SSL3_RT_INNER_CONTENT_TYPE => str_content_type = ", InnerContent".to_owned(),
            _ => {
                // BIO_snprintf into a 127-character buffer.
                let mut t = format!(", Unknown (content_type={content_type})");
                t.truncate(126);
                str_content_type = t;
            }
        }
        lookup(version, &SSL_VERSIONS, Some("???"))
            .unwrap_or("???")
            .to_owned()
    } else {
        let mut t = format!(
            "Not TLS data or unknown version (version={version}, content_type={content_type})"
        );
        t.truncate(126);
        t
    };
    let mut text = format!(
        "{str_write_p} {str_version}{str_content_type} [length {len:04x}]{str_details1}{str_details2}\n"
    );
    if len > 0 {
        text.push_str("   ");
        for (i, b) in buf.iter().enumerate() {
            if i % 16 == 0 && i > 0 {
                text.push_str("\n   ");
            }
            text.push_str(&format!(" {b:02x}"));
        }
        text.push('\n');
    }
    puts(&bio, &text);
    bio.flush();
}

const TLSEXT_TYPES: [(&str, i32); 32] = [
    ("server name", TLSEXT_TYPE_server_name),
    ("max fragment length", TLSEXT_TYPE_max_fragment_length),
    ("client certificate URL", TLSEXT_TYPE_client_certificate_url),
    ("trusted CA keys", TLSEXT_TYPE_trusted_ca_keys),
    ("truncated HMAC", TLSEXT_TYPE_truncated_hmac),
    ("status request", TLSEXT_TYPE_status_request),
    ("user mapping", TLSEXT_TYPE_user_mapping),
    ("client authz", TLSEXT_TYPE_client_authz),
    ("server authz", TLSEXT_TYPE_server_authz),
    ("cert type", TLSEXT_TYPE_cert_type),
    ("supported_groups", TLSEXT_TYPE_supported_groups),
    ("EC point formats", TLSEXT_TYPE_ec_point_formats),
    ("SRP", TLSEXT_TYPE_srp),
    ("signature algorithms", TLSEXT_TYPE_signature_algorithms),
    ("use SRTP", TLSEXT_TYPE_use_srtp),
    ("session ticket", TLSEXT_TYPE_session_ticket),
    ("renegotiation info", TLSEXT_TYPE_renegotiate),
    (
        "signed certificate timestamps",
        TLSEXT_TYPE_signed_certificate_timestamp,
    ),
    ("client cert type", TLSEXT_TYPE_client_cert_type),
    ("server cert type", TLSEXT_TYPE_server_cert_type),
    ("TLS padding", TLSEXT_TYPE_padding),
    ("next protocol", TLSEXT_TYPE_next_proto_neg),
    ("encrypt-then-mac", TLSEXT_TYPE_encrypt_then_mac),
    (
        "application layer protocol negotiation",
        TLSEXT_TYPE_application_layer_protocol_negotiation,
    ),
    ("extended master secret", TLSEXT_TYPE_extended_master_secret),
    ("compress certificate", TLSEXT_TYPE_compress_certificate),
    ("key share", TLSEXT_TYPE_key_share),
    ("supported versions", TLSEXT_TYPE_supported_versions),
    ("psk", TLSEXT_TYPE_psk),
    ("psk kex modes", TLSEXT_TYPE_psk_kex_modes),
    (
        "certificate authorities",
        TLSEXT_TYPE_certificate_authorities,
    ),
    ("post handshake auth", TLSEXT_TYPE_post_handshake_auth),
];

/// `tlsext_cb`.
pub fn tlsext_cb(
    _s: SslRef<'_>,
    client_server: i32,
    type_: i32,
    data: &[u8],
    arg: Option<ssl::BioRef<'_>>,
) {
    let Some(bio) = arg else { return };
    let extname = lookup(type_, &TLSEXT_TYPES, None)
        .or_else(|| (type_ == TLSEXT_TYPE_early_data).then_some("early_data"))
        .unwrap_or("unknown");
    let side = if client_server != 0 {
        "server"
    } else {
        "client"
    };
    puts(
        &bio,
        &format!(
            "TLS {side} extension \"{extname}\" (id={type_}), len={}\n",
            data.len()
        ),
    );
    ssl::bio_dump(&bio, data);
    bio.flush();
}

/// `generate_stateless_cookie_callback` (and `generate_cookie_callback`).
pub fn generate_cookie(s: SslRef<'_>) -> Option<Vec<u8>> {
    let secret = COOKIE_SECRET.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            let mut k = [0u8; COOKIE_SECRET_LENGTH];
            if !ssl::rand_bytes(&mut k) {
                eputs("error setting random cookie secret\n");
                return None;
            }
            *c = Some(k);
        }
        *c
    })?;
    let raw = if s.is_dtls() {
        let Some(peer) = rustyssl_ossl::sock::Addr::new() else {
            eputs("memory full\n");
            return None;
        };
        if let Some(rb) = s.rbio() {
            let _ = rb.dgram_get_peer(&peer);
        }
        addr_bytes(&peer)
    } else {
        super::s_socket::with_ourpeer(|p| p.and_then(addr_bytes))
    };
    let Some(buffer) = raw else {
        eputs("Failed getting peer address\n");
        return None;
    };
    let mac = ssl::hmac_sha1(
        &secret,
        &buffer,
        usize::try_from(DTLS1_COOKIE_LENGTH).unwrap_or(255),
    );
    if mac.is_none() {
        eputs("Error calculating HMAC-SHA1 of buffer with secret\n");
    }
    mac
}

/// The peer's port (as stored, network order) then its raw address.
fn addr_bytes(peer: &rustyssl_ossl::sock::Addr) -> Option<Vec<u8>> {
    let a = peer.rawaddress()?;
    let mut buffer = peer.rawport().to_ne_bytes().to_vec();
    buffer.extend_from_slice(&a);
    Some(buffer)
}

/// `verify_stateless_cookie_callback` (and `verify_cookie_callback`).
pub fn verify_cookie(s: SslRef<'_>, cookie: &[u8]) -> bool {
    if COOKIE_SECRET.with(|c| c.borrow().is_none()) {
        return false;
    }
    generate_cookie(s).is_some_and(|r| r == cookie)
}

/// One certificate of `ssl_excert_st`.
#[derive(Default)]
pub struct Excert {
    certform: i32,
    certfile: Option<String>,
    keyform: i32,
    keyfile: Option<String>,
    chainfile: Option<String>,
    cert: Option<Cert>,
    key: Option<Pkey>,
    chain: Option<CertStack>,
    build_chain: bool,
}

/// `SSL_EXCERT *`: the list, newest first (`ssl_excert_prepend`); `None` until an option.
pub type ExcertList = Option<Vec<Excert>>;

const CHAIN_FLAGS: [(&str, i32); 9] = [
    ("Overall Validity", CERT_PKEY_VALID),
    ("Sign with EE key", CERT_PKEY_SIGN),
    ("EE signature", CERT_PKEY_EE_SIGNATURE),
    ("CA signature", CERT_PKEY_CA_SIGNATURE),
    ("EE key parameters", CERT_PKEY_EE_PARAM),
    ("CA key parameters", CERT_PKEY_CA_PARAM),
    ("Explicitly sign with EE key", CERT_PKEY_EXPLICIT_SIGN),
    ("Issuer Name", CERT_PKEY_ISSUER_NAME),
    ("Certificate Type", CERT_PKEY_CERT_TYPE),
];

fn print_chain_flags(s: SslRef<'_>, flags: i32) {
    let mut text = String::new();
    for (name, v) in CHAIN_FLAGS {
        let ok = if flags & v != 0 { "OK" } else { "NOT OK" };
        text.push_str(&format!("\t{name}: {ok}\n"));
    }
    text.push_str("\tSuite B: ");
    if s.cert_flags() & core::ffi::c_long::from(SSL_CERT_FLAG_SUITEB_128_LOS) != 0 {
        text.push_str(if flags & CERT_PKEY_SUITEB != 0 {
            "OK\n"
        } else {
            "NOT OK\n"
        });
    } else {
        text.push_str("not tested\n");
    }
    eputs(&text);
}

/// `set_cert_cb`: uses every certificate chain reported valid, oldest option first.
fn set_cert_cb(s: SslRef<'_>) -> i32 {
    s.certs_clear();
    EXCERT.with(|list| {
        let list = list.borrow();
        for (i, exc) in list.iter().rev().enumerate() {
            let (Some(cert), Some(key)) = (&exc.cert, &exc.key) else {
                continue;
            };
            let rv = s.check_chain(cert, key, exc.chain.as_ref());
            eputs(&format!("Checking cert chain {}:\nSubject: ", i + 1));
            if let Some(be) = bio_err() {
                name_print(be, cert.subject_name());
            }
            eputs("\n");
            print_chain_flags(s, rv);
            if rv & CERT_PKEY_VALID != 0 {
                if !s.use_certificate(cert) || !s.use_private_key(key) {
                    return 0;
                }
                if exc.build_chain {
                    if !s.build_cert_chain(0) {
                        return 0;
                    }
                } else if let Some(ch) = &exc.chain
                    && !s.set1_chain(ch)
                {
                    return 0;
                }
            }
        }
        1
    })
}

/// `ssl_ctx_set_excert(ctx, exc)`: the context's certificate callback picks from the list.
pub fn ssl_ctx_set_excert(ctx: CtxRef<'_>, exc: ExcertList) {
    if let Some(list) = exc {
        EXCERT.with(|e| *e.borrow_mut() = list);
    }
    ctx.set_cert_cb(set_cert_cb);
}

/// Prepends an entry, inheriting the formats of the one before it (`ssl_excert_prepend`).
fn excert_prepend(list: &mut Vec<Excert>) {
    let (certform, keyform) = list
        .first()
        .map_or((format::PEM, format::PEM), |e| (e.certform, e.keyform));
    list.insert(
        0,
        Excert {
            certform,
            keyform,
            ..Excert::default()
        },
    );
}

/// `args_excert(opt, &exc)`.
pub fn args_excert(o: X, arg: &str, pexc: &mut ExcertList) -> bool {
    let prog = opt::prog();
    let list = pexc.get_or_insert_with(|| {
        let mut l = Vec::new();
        excert_prepend(&mut l);
        l
    });
    let fail = |pexc: &mut ExcertList| {
        io::print_errors();
        *pexc = None;
        false
    };
    match o {
        X::CERT => {
            if list.first().is_some_and(|e| e.certfile.is_some()) {
                excert_prepend(list);
            }
            if let Some(e) = list.first_mut() {
                e.certfile = Some(arg.to_owned());
            }
        }
        X::KEY => {
            if list.first().is_some_and(|e| e.keyfile.is_some()) {
                eprintf!("{prog}: Key already specified\n");
                return fail(pexc);
            }
            if let Some(e) = list.first_mut() {
                e.keyfile = Some(arg.to_owned());
            }
        }
        X::CHAIN => {
            if list.first().is_some_and(|e| e.chainfile.is_some()) {
                eprintf!("{prog}: Chain already specified\n");
                return fail(pexc);
            }
            if let Some(e) = list.first_mut() {
                e.chainfile = Some(arg.to_owned());
            }
        }
        X::CHAIN_BUILD => {
            if let Some(e) = list.first_mut() {
                e.build_chain = true;
            }
        }
        X::CERTFORM | X::KEYFORM => {
            let Some(f) = opt::parse_format(arg, opt::fmt_flags::ANY) else {
                return false;
            };
            if let Some(e) = list.first_mut() {
                if o == X::CERTFORM {
                    e.certform = f;
                } else {
                    e.keyform = f;
                }
            }
        }
    }
    true
}

/// `load_excert(&exc)`.
pub fn load_excert(pexc: &mut ExcertList) -> bool {
    let Some(list) = pexc else {
        return true;
    };
    // If nothing in list, free and set to NULL.
    if list.len() == 1 && list.first().is_some_and(|e| e.certfile.is_none()) {
        *pexc = None;
        return true;
    }
    for exc in list.iter_mut() {
        let Some(certfile) = exc.certfile.clone() else {
            eprintf!("Missing filename\n");
            return false;
        };
        exc.cert = apps::load_cert(Some(&certfile), exc.certform, Some("Server Certificate"));
        if exc.cert.is_none() {
            return false;
        }
        exc.key = match &exc.keyfile {
            Some(k) => apps::load_key(Some(k), exc.keyform, false, None, None, Some("server key")),
            None => apps::load_key(
                Some(&certfile),
                exc.certform,
                false,
                None,
                None,
                Some("server key"),
            ),
        };
        if exc.key.is_none() {
            return false;
        }
        if let Some(chain) = &exc.chainfile {
            let (ok, c) = apps::load_certs(Some(chain), false, None, None, Some("server chain"));
            if !ok {
                return false;
            }
            exc.chain = c;
        }
    }
    true
}

fn print_raw_cipherlist(s: SslRef<'_>) {
    if !s.is_server() {
        return;
    }
    let (num, list) = s.raw_cipherlist();
    if num != 2 {
        return;
    }
    let mut text = String::from("Client cipher list: ");
    for (i, &pair) in list.as_chunks::<2>().0.iter().enumerate() {
        if i > 0 {
            text.push(':');
        }
        match s.cipher_find(&pair) {
            Some(c) => text.push_str(&c.name().unwrap_or_default()),
            None if pair == [0, 0xff] => text.push_str("SCSV"),
            None => {
                text.push_str("0x");
                for b in pair {
                    text.push_str(&format!("{b:02X}"));
                }
            }
        }
    }
    text.push('\n');
    eputs(&text);
}

/// `hexencode`: lower-case hex, not `:`-delimited.
fn hexencode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// `print_verify_detail(s, bio)`.
pub fn print_verify_detail(s: SslRef<'_>, bio: &Bio) {
    let verify_err = s.verify_result();
    let mut text = String::new();
    if verify_err == core::ffi::c_long::from(X509_V_OK) {
        text.push_str("Verification: OK\n");
        if let Some(peer) = s.peername() {
            text.push_str(&format!("Verified peername: {peer}\n"));
        }
    } else {
        text.push_str(&format!(
            "Verification error: {}\n",
            ssl::verify_cert_error_string(verify_err)
        ));
    }
    let (mdpth, mspki) = s.dane_authority();
    if mdpth >= 0 {
        let (mdpth, usage, selector, mtype, data) = s.dane_tlsa();
        // The last 12 octets of the data tell TLSA records apart best.
        const TLSA_TAIL_SIZE: usize = 12;
        let (dots, hexdata) = if data.len() > TLSA_TAIL_SIZE {
            (
                "...",
                hexencode(data.get(data.len() - TLSA_TAIL_SIZE..).unwrap_or_default()),
            )
        } else {
            ("", hexencode(&data))
        };
        text.push_str(&format!(
            "DANE TLSA {usage} {selector} {mtype} {dots}{hexdata} "
        ));
        if s.peer_rpk().is_none() {
            let what = if mspki {
                "signed the peer"
            } else if mdpth != 0 {
                "matched the TA"
            } else {
                "matched the EE"
            };
            text.push_str(&format!("{what} certificate at depth {mdpth}\n"));
        } else {
            text.push_str("matched the peer raw public key\n");
        }
    }
    puts(bio, &text);
}

/// `print_ssl_summary(s)`.
pub fn print_ssl_summary(s: SslRef<'_>) {
    let Some(be) = bio_err() else { return };
    let peer = s.peer_certificate();
    let peer_rpk = s.peer_rpk();
    puts(be, &format!("Protocol version: {}\n", s.version_str()));
    print_raw_cipherlist(s);
    let cname = s
        .current_cipher()
        .and_then(|c| c.name())
        .unwrap_or_else(|| "(NONE)".to_owned());
    puts(be, &format!("Ciphersuite: {cname}\n"));
    do_print_sigalgs(be, s, false);
    if let Some(p) = &peer {
        puts(be, "Peer certificate: ");
        name_print(be, p.subject_name());
        puts(be, "\n");
        if let Some(nid) = s.peer_signature_nid() {
            puts(be, &format!("Hash used: {}\n", sn(nid)));
        }
        if let Some(sig) = s.peer_signature_name() {
            puts(be, &format!("Signature type: {sig}\n"));
        }
        print_verify_detail(s, be);
    } else if peer_rpk.is_some() {
        puts(be, "Peer used raw public key\n");
        if let Some(sig) = s.peer_signature_name() {
            puts(be, &format!("Signature type: {sig}\n"));
        }
        print_verify_detail(s, be);
    } else {
        puts(be, "No peer certificate or raw public key\n");
    }
    ssl_print_point_formats(be, s);
    if s.is_server() {
        ssl_print_groups(be, s, true);
    }
    ssl_print_tmp_key(be, s);
}

/// `config_ctx(cctx, str, ctx)`: the `-S` options, as (flag, value) pairs.
pub fn config_ctx(cctx: &ConfCtx, args: &[(String, Option<String>)], ctx: CtxRef<'_>) -> bool {
    cctx.set_ssl_ctx(ctx);
    for (flag, arg) in args {
        if cctx.cmd(flag, arg.as_deref()) <= 0 {
            eprintf!(
                "Call to SSL_CONF_cmd({flag}, {}) failed\n",
                arg.as_deref().unwrap_or("<NULL>")
            );
            io::print_errors();
            return false;
        }
    }
    if !cctx.finish() {
        eprintf!("Error finishing context\n");
        io::print_errors();
        return false;
    }
    true
}

/// `ssl_ctx_add_crls(ctx, crls, crl_download)`.
pub fn ssl_ctx_add_crls(ctx: CtxRef<'_>, crls: Option<&CrlStack>, crl_download: bool) {
    if let Some(c) = crls {
        ctx.add_crls_to_cert_store(c);
    }
    if crl_download {
        ctx.cert_store_setup_crl_download();
    }
}

/// `ssl_load_stores(ctx, vfyCApath, vfyCAfile, vfyCAstore, chCApath, chCAfile, chCAstore,
/// crls, crl_download)`.
#[allow(clippy::too_many_arguments)]
pub fn ssl_load_stores(
    ctx: CtxRef<'_>,
    vfy_ca_path: Option<&str>,
    vfy_ca_file: Option<&str>,
    vfy_ca_store: Option<&str>,
    ch_ca_path: Option<&str>,
    ch_ca_file: Option<&str>,
    ch_ca_store: Option<&str>,
    crls: Option<&CrlStack>,
    crl_download: bool,
) -> bool {
    if vfy_ca_path.is_some() || vfy_ca_file.is_some() || vfy_ca_store.is_some() {
        let Some(vfy) = Store::new() else {
            return false;
        };
        if vfy_ca_file.is_some_and(|f| !vfy.load_file(f))
            || vfy_ca_path.is_some_and(|p| !vfy.load_path(p))
            || vfy_ca_store.is_some_and(|s| !vfy.load_store(s))
        {
            return false;
        }
        if let Some(c) = crls {
            vfy.add_crls(c);
        }
        if !ctx.set1_verify_cert_store(&vfy) {
            return false;
        }
        if crl_download {
            vfy.setup_crl_download();
        }
    }
    if ch_ca_path.is_some() || ch_ca_file.is_some() || ch_ca_store.is_some() {
        let Some(ch) = Store::new() else { return false };
        if ch_ca_file.is_some_and(|f| !ch.load_file(f))
            || ch_ca_path.is_some_and(|p| !ch.load_path(p))
            || ch_ca_store.is_some_and(|s| !ch.load_store(s))
        {
            return false;
        }
        if !ctx.set1_chain_cert_store(&ch) {
            return false;
        }
    }
    true
}

const CALLBACK_TYPES: [(&str, i32); 16] = [
    ("Supported Ciphersuite", SSL_SECOP_CIPHER_SUPPORTED),
    ("Shared Ciphersuite", SSL_SECOP_CIPHER_SHARED),
    ("Check Ciphersuite", SSL_SECOP_CIPHER_CHECK),
    ("Temp DH key bits", SSL_SECOP_TMP_DH),
    ("Supported Curve", SSL_SECOP_CURVE_SUPPORTED),
    ("Shared Curve", SSL_SECOP_CURVE_SHARED),
    ("Check Curve", SSL_SECOP_CURVE_CHECK),
    ("Supported Signature Algorithm", SSL_SECOP_SIGALG_SUPPORTED),
    ("Shared Signature Algorithm", SSL_SECOP_SIGALG_SHARED),
    ("Check Signature Algorithm", SSL_SECOP_SIGALG_CHECK),
    ("Signature Algorithm mask", SSL_SECOP_SIGALG_MASK),
    ("Certificate chain EE key", SSL_SECOP_EE_KEY),
    ("Certificate chain CA key", SSL_SECOP_CA_KEY),
    ("Certificate chain CA digest", SSL_SECOP_CA_MD),
    ("SSL compression", SSL_SECOP_COMPRESSION),
    ("Session ticket", SSL_SECOP_TICKET),
];

const SIGNATURE_TLS13_SCHEMES: [(&str, i32); 19] = [
    ("rsa_pkcs1_sha1", 0x0201),
    ("ecdsa_sha1", 0x0203),
    ("rsa_pkcs1_sha256", 0x0401),
    ("ecdsa_secp256r1_sha256", 0x0403),
    ("rsa_pkcs1_sha384", 0x0501),
    ("ecdsa_secp384r1_sha384", 0x0503),
    ("rsa_pkcs1_sha512", 0x0601),
    ("ecdsa_secp521r1_sha512", 0x0603),
    ("rsa_pss_rsae_sha256", 0x0804),
    ("rsa_pss_rsae_sha384", 0x0805),
    ("rsa_pss_rsae_sha512", 0x0806),
    ("ed25519", 0x0807),
    ("ed448", 0x0808),
    ("rsa_pss_pss_sha256", 0x0809),
    ("rsa_pss_pss_sha384", 0x080a),
    ("rsa_pss_pss_sha512", 0x080b),
    ("gostr34102001", 0xeded),
    ("gostr34102012_256", 0xeeee),
    ("gostr34102012_512", 0xefef),
];

const SIGNATURE_TLS12_ALGS: [(&str, i32); 4] = [
    ("anonymous", TLSEXT_signature_anonymous),
    ("RSA", TLSEXT_signature_rsa),
    ("DSA", TLSEXT_signature_dsa),
    ("ECDSA", TLSEXT_signature_ecdsa),
];

const SIGNATURE_TLS12_HASHES: [(&str, i32); 7] = [
    ("none", TLSEXT_hash_none),
    ("MD5", TLSEXT_hash_md5),
    ("SHA1", TLSEXT_hash_sha1),
    ("SHA224", TLSEXT_hash_sha224),
    ("SHA256", TLSEXT_hash_sha256),
    ("SHA384", TLSEXT_hash_sha384),
    ("SHA512", TLSEXT_hash_sha512),
];

/// `security_callback_debug`.
fn security_callback_debug(a: &SecArgs<'_>) -> i32 {
    let rv = a.rv;
    if rv == 1 && SEC_VERBOSE.with(Cell::get) < 2 {
        return 1;
    }
    let mut text = String::from("Security callback: ");
    let nm = lookup(a.op, &CALLBACK_TYPES, None);
    let mut show_nm = nm.is_some();
    let mut show_bits = true;
    let mut cert_md = false;
    match a.op {
        SSL_SECOP_TICKET | SSL_SECOP_COMPRESSION => {
            show_bits = false;
            show_nm = false;
        }
        SSL_SECOP_VERSION => {
            let v = lookup(a.nid, &SSL_VERSIONS, Some("???")).unwrap_or("???");
            text.push_str(&format!("Version={v}"));
            show_bits = false;
            show_nm = false;
        }
        SSL_SECOP_CA_MD => cert_md = true,
        SSL_SECOP_SIGALG_SUPPORTED
        | SSL_SECOP_SIGALG_SHARED
        | SSL_SECOP_SIGALG_CHECK
        | SSL_SECOP_SIGALG_MASK => show_nm = false,
        _ => {}
    }
    if show_nm && let Some(n) = nm {
        text.push_str(&format!("{n}="));
    }
    match &a.other {
        SecOther::Cipher(c) => {
            text.push_str(&c.and_then(|c| c.name()).unwrap_or_default());
        }
        SecOther::Curve => {
            let cname = ssl::ec_curve_nid2nist(a.nid)
                .or_else(|| ssl::nid2sn(a.nid))
                .unwrap_or_default();
            text.push_str(&cname);
        }
        SecOther::Cert(x) => {
            if let Some(x) = x {
                if cert_md {
                    text.push_str(&ssl::nid2sn(ssl::cert_signature_nid(x)).unwrap_or_default());
                } else {
                    match ssl::cert_pubkey(x) {
                        None => text.push_str("Public key missing"),
                        Some(k) => text.push_str(&format!(
                            "{}, bits={}",
                            k.type_name().unwrap_or_else(|| "<NULL>".to_owned()),
                            k.bits()
                        )),
                    }
                }
            }
        }
        SecOther::Sigalg(salg) => {
            let raw = (i32::from(salg[0]) << 8) + i32::from(salg[1]);
            match nm {
                Some(n) => text.push_str(n),
                None => text.push_str(&format!("s_cb.c:security_callback_debug op=0x{:x}", a.op)),
            }
            match lookup(raw, &SIGNATURE_TLS13_SCHEMES, None) {
                Some(name) => text.push_str(&format!(" scheme={name}")),
                None => {
                    let alg = lookup(i32::from(salg[1]), &SIGNATURE_TLS12_ALGS, None);
                    let hash = lookup(i32::from(salg[0]), &SIGNATURE_TLS12_HASHES, None);
                    match (alg, hash) {
                        (Some(a), Some(h)) => {
                            text.push_str(&format!(" digest={h}, algorithm={a}"));
                        }
                        _ => text.push_str(&format!(" scheme=unknown(0x{raw:04x})")),
                    }
                }
            }
        }
        SecOther::None => {}
    }
    if show_bits {
        text.push_str(&format!(", security bits={}", a.bits));
    }
    text.push_str(&format!(": {}\n", if rv != 0 { "yes" } else { "no" }));
    eputs(&text);
    rv
}

/// `ssl_ctx_security_debug(ctx, verbose)`.
pub fn ssl_ctx_security_debug(ctx: CtxRef<'_>, verbose: i32) {
    SEC_VERBOSE.with(|v| v.set(verbose));
    ctx.wrap_security_callback(security_callback_debug);
}

fn keylog_callback(line: &str) {
    BIO_KEYLOG.with(|k| match k.borrow().as_ref() {
        None => eputs("Keylog callback is invoked without valid file!\n"),
        Some(b) => {
            // Concurrent writers may share the file: the line is written at once.
            let _ = b.write_all(format!("{line}\n").as_bytes());
            b.flush();
        }
    });
}

/// `set_keylog_file(ctx, keylog_file)`: true on failure (as the C function's 1).
pub fn set_keylog_file(ctx: Option<CtxRef<'_>>, keylog_file: Option<&str>) -> bool {
    BIO_KEYLOG.with(|k| *k.borrow_mut() = None);
    let (Some(ctx), Some(file)) = (ctx, keylog_file) else {
        // Keylogging is disabled, OK.
        return false;
    };
    // Append rather than write, to allow concurrent modification.
    let Some(b) = Bio::new_file(file, "a") else {
        eprintf!("Error writing keylog file {file}\n");
        return true;
    };
    // A header for seekable, empty files (not pipes).
    if b.tell() == 0 {
        let _ = b.write_all(b"# SSL/TLS secrets log file, generated by OpenSSL\n");
        b.flush();
    }
    BIO_KEYLOG.with(|k| *k.borrow_mut() = Some(b));
    ctx.set_keylog_callback(keylog_callback);
    false
}

/// `print_ca_names(bio, s)`.
pub fn print_ca_names(bio: &Bio, s: SslRef<'_>) {
    let cs = if s.is_server() { "server" } else { "client" };
    let names = s.peer_ca_list();
    if names.is_empty() {
        if !s.is_server() {
            puts(bio, &format!("---\nNo {cs} certificate CA names sent\n"));
        }
        return;
    }
    puts(bio, &format!("---\nAcceptable {cs} certificate CA names\n"));
    for nm in names {
        name_print(bio, nm);
        puts(bio, "\n");
    }
}

/// `ssl_print_secure_renegotiation_notes(bio, s)`.
pub fn ssl_print_secure_renegotiation_notes(bio: &Bio, s: SslRef<'_>) {
    if s.is_dtls() || s.version() < TLS1_3_VERSION {
        let not = if s.secure_renegotiation_support() {
            ""
        } else {
            " NOT"
        };
        puts(bio, &format!("Secure Renegotiation IS{not} supported\n"));
    } else {
        puts(bio, "This TLS version forbids renegotiation.\n");
    }
}

/// `ctx_set_verify_locations` of `apps.c`.
pub fn ctx_set_verify_locations(
    ctx: CtxRef<'_>,
    ca_file: Option<&str>,
    no_ca_file: bool,
    ca_path: Option<&str>,
    no_ca_path: bool,
    ca_store: Option<&str>,
    no_ca_store: bool,
) -> bool {
    if ca_file.is_none() && ca_path.is_none() && ca_store.is_none() {
        if !no_ca_file && !ctx.set_default_verify_file() {
            return false;
        }
        if !no_ca_path && !ctx.set_default_verify_dir() {
            return false;
        }
        if !no_ca_store && !ctx.set_default_verify_store() {
            return false;
        }
        return true;
    }
    if ca_file.is_some_and(|f| !ctx.load_verify_file(f)) {
        return false;
    }
    if ca_path.is_some_and(|p| !ctx.load_verify_dir(p)) {
        return false;
    }
    !ca_store.is_some_and(|s| !ctx.load_verify_store(s))
}

/// `ctx_set_ctlog_list_file` of `apps.c`.
pub fn ctx_set_ctlog_list_file(ctx: CtxRef<'_>, path: Option<&str>) -> bool {
    ctx.set_ctlog_list_file(path)
}

/// `next_protos_parse` of `apps.c`: a comma-separated list in wire format, `None` if empty,
/// too long, or with an element over 255 octets.
pub fn next_protos_parse(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() >= 65535 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    for part in bytes.split(|&b| b == b',') {
        // Zero-length elements are invalid on the wire: extra commas are skipped.
        if part.is_empty() {
            continue;
        }
        let n = u8::try_from(part.len()).ok()?;
        out.push(n);
        out.extend_from_slice(part);
    }
    (!out.is_empty()).then_some(out)
}

/// `wait_for_async` of `apps.c`.
pub fn wait_for_async(s: SslRef<'_>) {
    let Some(fds) = s.all_async_fds() else { return };
    if fds.is_empty() {
        return;
    }
    let _ = rustyssl_ossl::sock::select(&fds, &[], None);
}

/// `SRP_ARG` of `s_apps.h`: the client's SRP settings.
#[derive(Clone, Default)]
pub struct SrpArg {
    pub srppassin: Option<String>,
    pub srplogin: Option<String>,
    pub msg: bool,
    pub debug: bool,
    pub amp: bool,
    pub strength: i32,
}

thread_local! {
    static SRP_ARG: RefCell<SrpArg> = RefCell::new(SrpArg::default());
    static SRP_SRV: RefCell<SrpSrvParm> = RefCell::new(SrpSrvParm::default());
}

fn ssl_srp_verify_param_cb(s: SslRef<'_>) -> i32 {
    let arg = SRP_ARG.with(|a| a.borrow().clone());
    let Some((n, g)) = s.srp_n_g() else {
        return 0;
    };
    let Some(be) = bio_err() else { return 0 };
    if arg.debug || arg.msg || arg.amp {
        puts(be, "SRP parameters:\n");
        puts(be, "\tN=");
        n.print(be);
        puts(be, "\n\tg=");
        g.print(be);
        puts(be, "\n");
    }
    if g.srp_known_gn(n) {
        return 1;
    }
    if arg.amp {
        if arg.debug {
            puts(
                be,
                "SRP param N and g are not known params, going to check deeper.\n",
            );
        }
        // BN_BITS: the size of a BIGNUM double word.
        if g.num_bits() <= 128 && ssl::BnRef::srp_verify_n_and_g(n, g) {
            return 1;
        }
    }
    puts(be, "SRP param N and g rejected.\n");
    0
}

/// `PWD_STRLEN`.
const PWD_STRLEN: usize = 1024;

fn ssl_give_srp_client_pwd_cb(_s: SslRef<'_>) -> Option<String> {
    let passin = SRP_ARG.with(|a| a.borrow().srppassin.clone());
    match srpx::password_callback(PWD_STRLEN, false, passin.as_deref(), Some("SRP user")) {
        Ok(p) => Some(String::from_utf8_lossy(&p).into_owned()),
        Err(0) => Some(String::new()),
        Err(_) => {
            eputs("Can't read Password\n");
            None
        }
    }
}

/// `set_up_srp_arg(ctx, srp_arg, srp_lateuser, c_msg, c_debug)`.
pub fn set_up_srp_arg(
    ctx: CtxRef<'_>,
    arg: &SrpArg,
    lateuser: bool,
    msg: bool,
    debug: bool,
) -> bool {
    if !lateuser && !ctx.set_srp_username(arg.srplogin.as_deref().unwrap_or_default()) {
        eprintf!("Unable to set SRP username\n");
        return false;
    }
    let mut a = arg.clone();
    a.msg = msg;
    a.debug = debug;
    let amp = a.amp;
    let strength = a.strength;
    SRP_ARG.with(|s| *s.borrow_mut() = a);
    ctx.set_srp_client_pwd_callback(ssl_give_srp_client_pwd_cb);
    ctx.set_srp_strength(strength);
    if msg || debug || !amp {
        ctx.set_srp_verify_param_callback(ssl_srp_verify_param_cb);
    }
    true
}

/// `srpsrvparm`: the server's SRP state.
#[derive(Default)]
pub struct SrpSrvParm {
    login: Option<String>,
    vb: Option<ssl::SrpVbase>,
    user: Option<ssl::SrpUser>,
}

fn ssl_srp_server_param_cb(s: SslRef<'_>, ad: &mut i32) -> i32 {
    SRP_SRV.with(|p| {
        let mut p = p.borrow_mut();
        if p.login.is_none() && p.user.is_none() {
            p.login = s.srp_username();
            eputs(&format!(
                "SRP username = \"{}\"\n",
                p.login.as_deref().unwrap_or("<NULL>")
            ));
            return -1;
        }
        let mut ret = SSL3_AL_FATAL;
        let login = p.login.clone().unwrap_or_else(|| "<NULL>".to_owned());
        match &p.user {
            None => eputs(&format!("User {login} doesn't exist\n")),
            Some(u) => {
                if s.set_srp_server_param(u) < 0 {
                    *ad = SSL_AD_INTERNAL_ERROR;
                } else {
                    let info = u.info().unwrap_or_else(|| "<NULL>".to_owned());
                    eputs(&format!(
                        "SRP parameters set: username = \"{login}\" info=\"{info}\"\n"
                    ));
                    ret = SSL_ERROR_NONE;
                }
            }
        }
        p.user = None;
        p.login = None;
        ret
    })
}

/// `set_up_srp_verifier_file(ctx, srp_callback_parm, srpuserseed, srp_verifier_file)`.
pub fn set_up_srp_verifier_file(ctx: CtxRef<'_>, seed: Option<&str>, file: &str) -> bool {
    let Some(vb) = ssl::SrpVbase::new(seed) else {
        eprintf!("Failed to initialize SRP verifier file\n");
        return false;
    };
    let ret = vb.init(file);
    if ret != SRP_NO_ERROR {
        eprintf!("Cannot initialize SRP verifier file \"{file}\":ret={ret}\n");
        return false;
    }
    SRP_SRV.with(|p| {
        *p.borrow_mut() = SrpSrvParm {
            login: None,
            vb: Some(vb),
            user: None,
        };
    });
    ctx.set_verify(SSL_VERIFY_NONE, Some(verify_callback));
    ctx.set_srp_username_callback(ssl_srp_server_param_cb);
    true
}

/// `lookup_srp_user(srp_callback_parm, bio_s_out)`.
pub fn lookup_srp_user(bio_s_out: &Bio) {
    SRP_SRV.with(|p| {
        let mut p = p.borrow_mut();
        let login = p.login.clone();
        p.user = match (&p.vb, login) {
            (Some(vb), Some(l)) => vb.get1_by_user(&l),
            _ => None,
        };
        match &p.user {
            Some(u) => puts(
                bio_s_out,
                &format!(
                    "LOOKUP done {}\n",
                    u.info().unwrap_or_else(|| "<NULL>".to_owned())
                ),
            ),
            None => puts(bio_s_out, "LOOKUP not successful\n"),
        }
    });
}

/// The server's SRP login (`srp_callback_parm.login`).
pub fn srp_login() -> Option<String> {
    SRP_SRV.with(|p| p.borrow().login.clone())
}
