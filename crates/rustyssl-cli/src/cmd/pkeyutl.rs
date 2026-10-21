//! `openssl pkeyutl` (`apps/pkeyutl.c`).

use rustyssl_ossl::abi::{
    EVP_MAX_MD_SIZE, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_DERIVE,
    EVP_PKEY_OP_ENCAPSULATE, EVP_PKEY_OP_ENCRYPT, EVP_PKEY_OP_SIGN, EVP_PKEY_OP_VERIFY,
    EVP_PKEY_OP_VERIFYRECOVER,
};
use rustyssl_ossl::pkey::{MdPkeyCtx, Pkey, PkeyCtx};
use rustyssl_ossl::{Bio, obj, ui};

use crate::generated::options::pkeyutl::{OPTIONS, Opt};
use crate::lib::apps::{
    ConfigFile, app_load_config_modules, app_passwd, bio_open_default, bio_open_owner, bio_to_mem,
    load_cert, load_key, load_pubkey, pkey_ctrl_string,
};
use crate::lib::engine::Engine;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyType {
    None,
    Private,
    Public,
    Cert,
}

/// `TBUF_MAXSIZE`.
const TBUF_MAXSIZE: usize = 2048;

/// The operation's context: a key context, or (raw input) a digest context over one.
enum Ctx {
    Plain(PkeyCtx),
    Md(MdPkeyCtx),
}

impl Ctx {
    fn pkey_ctx(&self) -> &PkeyCtx {
        match self {
            Ctx::Plain(c) => c,
            Ctx::Md(m) => m.pkey_ctx(),
        }
    }
}

/// `only_nomd`: whether the key signs only without a digest (a mandatory "UNDEF").
fn only_nomd(pkey: &Pkey) -> bool {
    let (deftype, defname) = pkey.default_digest_name();
    deftype == 2 && defname == "UNDEF"
}

/// `get_pkey`.
fn get_pkey(
    kdfalg: Option<&str>,
    keyfile: Option<&str>,
    keyform: i32,
    key_type: KeyType,
    passinarg: Option<&str>,
    pkey_op: i32,
    e: Option<&Engine>,
) -> Option<Pkey> {
    if (pkey_op == EVP_PKEY_OP_SIGN
        || pkey_op == EVP_PKEY_OP_DECRYPT
        || pkey_op == EVP_PKEY_OP_DERIVE)
        && key_type != KeyType::Private
        && kdfalg.is_none()
    {
        eprintf!("A private key is needed for this operation\n");
        return None;
    }
    let Some((passin, _)) = app_passwd(passinarg, None) else {
        eprintf!("Error getting password\n");
        return None;
    };
    match key_type {
        KeyType::Private => load_key(
            keyfile,
            keyform,
            false,
            passin.as_ref().map(|p| p.as_str()),
            e,
            Some("private key"),
        ),
        KeyType::Public => load_pubkey(keyfile, keyform, false, None, e, Some("public key")),
        KeyType::Cert => load_cert(keyfile, keyform, Some("Certificate")).and_then(|x| x.pubkey()),
        KeyType::None => None,
    }
}

/// `init_ctx`.
#[allow(clippy::too_many_arguments)]
fn init_ctx(
    kdfalg: Option<&str>,
    pkey_op: i32,
    e: Option<&Engine>,
    engine_impl: bool,
    rawin: bool,
    pkey: Option<&Pkey>,
    digestname: Option<&str>,
    kemop: Option<&str>,
) -> Option<Ctx> {
    let impl_ = if engine_impl { e } else { None };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let ctx = if let Some(kdf) = kdfalg {
        let mut kdfnid = obj::sn2nid(kdf);
        if kdfnid == 0 {
            kdfnid = obj::ln2nid(kdf);
            if kdfnid == 0 {
                eprintf!("The given KDF \"{kdf}\" is unknown.\n");
                return None;
            }
        }
        if impl_.is_some() {
            PkeyCtx::new_id(kdfnid, impl_)
        } else {
            PkeyCtx::from_name(lc.as_deref(), kdf, pq.as_deref())
        }
    } else {
        let pkey = pkey?;
        if impl_.is_some() {
            PkeyCtx::new(pkey, impl_)
        } else {
            PkeyCtx::from_pkey(lc.as_deref(), Some(pkey), pq.as_deref())
        }
    }?;
    if rawin {
        let m = MdPkeyCtx::new(ctx)?;
        let pkey = pkey?;
        let rv = match pkey_op {
            EVP_PKEY_OP_SIGN => m.sign_init(digestname, lc.as_deref(), pq.as_deref(), pkey),
            EVP_PKEY_OP_VERIFY => m.verify_init(digestname, lc.as_deref(), pq.as_deref(), pkey),
            _ => -1,
        };
        return (rv > 0).then_some(Ctx::Md(m));
    }
    let rv = match pkey_op {
        EVP_PKEY_OP_SIGN => ctx.sign_init(),
        EVP_PKEY_OP_VERIFY => ctx.verify_init(),
        EVP_PKEY_OP_VERIFYRECOVER => ctx.verify_recover_init(),
        EVP_PKEY_OP_ENCRYPT => ctx.encrypt_init(),
        EVP_PKEY_OP_DECRYPT => ctx.decrypt_init(),
        EVP_PKEY_OP_DERIVE => ctx.derive_init(),
        EVP_PKEY_OP_ENCAPSULATE | EVP_PKEY_OP_DECAPSULATE => {
            let mut rv = if pkey_op == EVP_PKEY_OP_ENCAPSULATE {
                ctx.encapsulate_init()
            } else {
                ctx.decapsulate_init()
            };
            if rv > 0
                && let Some(op) = kemop
            {
                rv = ctx.set_kem_op(op);
            }
            rv
        }
        _ => -1,
    };
    (rv > 0).then_some(Ctx::Plain(ctx))
}

/// `setup_peer`.
fn setup_peer(ctx: &PkeyCtx, peerform: i32, file: &str, e: Option<&Engine>) -> bool {
    let engine = if peerform == format::ENGINE { e } else { None };
    let Some(peer) = load_pubkey(Some(file), peerform, false, None, engine, Some("peer key"))
    else {
        eprintf!("Error reading peer key {file}\n");
        return false;
    };
    let (pt, kt) = (peer.type_name(), ctx.pkey_type_name());
    if pt != kt {
        eprintf!(
            "Type of peer public key: {} does not match type of private key: {}\n",
            pt.as_deref().unwrap_or("<NULL>"),
            kt.as_deref().unwrap_or("<NULL>")
        );
        false
    } else {
        ctx.derive_set_peer(&peer) > 0
    }
}

/// `do_keyop`: `out` and `secret` are `None` for the length queries.
fn do_keyop(
    ctx: &PkeyCtx,
    pkey_op: i32,
    out: Option<&mut [u8]>,
    outlen: &mut usize,
    input: &[u8],
    secret: Option<&mut [u8]>,
    secretlen: &mut usize,
) -> i32 {
    match pkey_op {
        EVP_PKEY_OP_VERIFYRECOVER => ctx.verify_recover(out, outlen, input),
        EVP_PKEY_OP_SIGN => ctx.sign(out, outlen, input),
        EVP_PKEY_OP_ENCRYPT => ctx.encrypt(out, outlen, input),
        EVP_PKEY_OP_DECRYPT => ctx.decrypt(out, outlen, input),
        EVP_PKEY_OP_DERIVE => ctx.derive(out, outlen),
        EVP_PKEY_OP_ENCAPSULATE => ctx.encapsulate(out, outlen, secret, secretlen),
        EVP_PKEY_OP_DECAPSULATE => ctx.decapsulate(secret, secretlen, input),
        _ => 0,
    }
}

/// `do_raw_keyop`: signing (the signature returned) or verifying `sig`, over the input.
fn do_raw_keyop(
    pkey_op: i32,
    m: &MdPkeyCtx,
    pkey: &Pkey,
    input: &Bio,
    filesize: i64,
    sig: &[u8],
) -> (i32, Vec<u8>) {
    let mut out = Vec::new();
    if only_nomd(pkey) {
        let Ok(size) = usize::try_from(filesize) else {
            eprintf!("Error: unable to determine file size for oneshot operation\n");
            return (0, out);
        };
        let mut mbuf = vec![0u8; size];
        let n = input.read(&mut mbuf);
        if usize::try_from(n).ok() != Some(size) {
            eprintf!("Error reading raw input data\n");
            return (0, out);
        }
        let rv = if pkey_op == EVP_PKEY_OP_VERIFY {
            m.digest_verify(sig, &mbuf)
        } else {
            let mut len = 0;
            let mut rv = m.digest_sign(None, &mut len, &mbuf);
            if rv == 1 {
                out = vec![0u8; len];
                rv = m.digest_sign(Some(&mut out), &mut len, &mbuf);
                out.truncate(len);
            }
            rv
        };
        return (rv, out);
    }
    let mut tbuf = [0u8; TBUF_MAXSIZE];
    let verify = pkey_op == EVP_PKEY_OP_VERIFY;
    loop {
        let n = input.read(&mut tbuf);
        if n == 0 {
            break;
        }
        let Some(chunk) = usize::try_from(n).ok().and_then(|n| tbuf.get(..n)) else {
            eprintf!("Error reading raw input data\n");
            return (0, out);
        };
        let rv = if verify {
            m.verify_update(chunk)
        } else {
            m.sign_update(chunk)
        };
        if rv != 1 {
            if verify {
                eprintf!("Error verifying raw input data\n");
            } else {
                eprintf!("Error signing raw input data\n");
            }
            return (0, out);
        }
    }
    if verify {
        return (m.verify_final(sig), out);
    }
    let mut len = 0;
    let mut rv = m.sign_final(None, &mut len);
    if rv == 1 {
        out = vec![0u8; len];
        rv = m.sign_final(Some(&mut out), &mut len);
        out.truncate(len);
    }
    (rv, out)
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut e = None;
    let mut _conf = None;
    let (mut infile, mut outfile, mut secoutfile, mut sigfile, mut passinarg): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None, None);
    let (mut hexdump, mut asn1parse, mut rev, mut engine_impl, mut rawin) =
        (false, false, false, false, false);
    let (mut keyform, mut peerform) = (format::UNDEF, format::UNDEF);
    let (mut pkey_op, mut key_type) = (EVP_PKEY_OP_SIGN, KeyType::Private);
    let (mut inkey, mut peerkey, mut kdfalg, mut digestname, mut kemop): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None, None);
    let mut kdflen = 0;
    let (mut pkeyopts, mut pkeyopts_passin): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::SECOUT => secoutfile = Some(p.arg().to_owned()),
            Opt::SIGFILE => sigfile = Some(p.arg().to_owned()),
            Opt::ENGINE_IMPL => engine_impl = true,
            Opt::INKEY => inkey = Some(p.arg().to_owned()),
            Opt::PEERKEY => peerkey = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PEERFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => peerform = f,
                None => return usage(),
            },
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyform = f,
                None => return usage(),
            },
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::CONFIG => {
                _conf = app_load_config_modules(Some(&ConfigFile::Given(p.arg().to_owned())));
                if _conf.is_none() {
                    return 1;
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PUBIN => key_type = KeyType::Public,
            Opt::CERTIN => key_type = KeyType::Cert,
            Opt::ASN1PARSE => asn1parse = true,
            Opt::HEXDUMP => hexdump = true,
            Opt::SIGN => pkey_op = EVP_PKEY_OP_SIGN,
            Opt::VERIFY => pkey_op = EVP_PKEY_OP_VERIFY,
            Opt::VERIFYRECOVER => pkey_op = EVP_PKEY_OP_VERIFYRECOVER,
            Opt::ENCRYPT => pkey_op = EVP_PKEY_OP_ENCRYPT,
            Opt::DECRYPT => pkey_op = EVP_PKEY_OP_DECRYPT,
            Opt::DERIVE => pkey_op = EVP_PKEY_OP_DERIVE,
            Opt::DECAP => pkey_op = EVP_PKEY_OP_DECAPSULATE,
            Opt::ENCAP => (key_type, pkey_op) = (KeyType::Public, EVP_PKEY_OP_ENCAPSULATE),
            Opt::KEMOP => kemop = Some(p.arg().to_owned()),
            Opt::KDF => {
                (pkey_op, key_type) = (EVP_PKEY_OP_DERIVE, KeyType::None);
                kdfalg = Some(p.arg().to_owned());
            }
            Opt::KDFLEN => kdflen = crate::lib::apps::atoi(p.arg()),
            Opt::REV => rev = true,
            Opt::PKEYOPT => pkeyopts.push(p.arg().to_owned()),
            Opt::PKEYOPT_PASSIN => pkeyopts_passin.push(p.arg().to_owned()),
            Opt::RAWIN => rawin = true,
            Opt::DIGEST => digestname = Some(p.arg().to_owned()),
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return 1;
    }
    if digestname.is_some() {
        rawin = true;
    }
    if kdfalg.is_some() {
        if kdflen == 0 {
            eprintf!("{prog}: no KDF length given (-kdflen parameter).\n");
            return usage();
        }
    } else if inkey.is_none() {
        eprintf!("{prog}: no private key given (-inkey parameter).\n");
        return usage();
    } else if peerkey.is_some() && pkey_op != EVP_PKEY_OP_DERIVE {
        eprintf!("{prog}: -peerkey option not allowed without -derive.\n");
        return usage();
    } else if peerkey.is_none() && pkey_op == EVP_PKEY_OP_DERIVE {
        eprintf!("{prog}: missing -peerkey option for -derive operation.\n");
        return usage();
    }
    let pkey = get_pkey(
        kdfalg.as_deref(),
        inkey.as_deref(),
        keyform,
        key_type,
        passinarg.as_deref(),
        pkey_op,
        e.as_ref(),
    );
    if key_type != KeyType::None && pkey.is_none() {
        eprintf!("{prog}: Error loading key\n");
        return 1;
    }
    if pkey_op == EVP_PKEY_OP_VERIFYRECOVER && !pkey.as_ref().is_some_and(|k| k.is_a("RSA")) {
        eprintf!("{prog}: -verifyrecover can be used only with RSA\n");
        return 1;
    }
    if pkey_op == EVP_PKEY_OP_SIGN || pkey_op == EVP_PKEY_OP_VERIFY {
        if let Some(k) = &pkey
            && only_nomd(k)
        {
            if digestname.is_some() {
                let alg = k.type_name();
                eprintf!(
                    "{prog}: -digest (prehash) is not supported with {}\n",
                    alg.as_deref().unwrap_or("(unknown key type)")
                );
                return 1;
            }
            rawin = true;
        }
    } else if digestname.is_some() || rawin {
        eprintf!("{prog}: -digest and -rawin can only be used with -sign or -verify\n");
        return usage();
    }
    if rawin && rev {
        eprintf!("{prog}: -rev cannot be used with raw input\n");
        return usage();
    }
    let Some(ctx) = init_ctx(
        kdfalg.as_deref(),
        pkey_op,
        e.as_ref(),
        engine_impl,
        rawin,
        pkey.as_ref(),
        digestname.as_deref(),
        kemop.as_deref(),
    ) else {
        eprintf!("{prog}: Error initializing context\n");
        return 1;
    };
    let pctx = ctx.pkey_ctx();
    if let Some(pk) = &peerkey
        && !setup_peer(pctx, peerform, pk, e.as_ref())
    {
        eprintf!("{prog}: Error setting up peer key\n");
        return 1;
    }
    for o in &pkeyopts {
        if pkey_ctrl_string(pctx.borrow(), o) <= 0 {
            eprintf!("{prog}: Can't set parameter \"{o}\":\n");
            return 1;
        }
    }
    for o in &pkeyopts_passin {
        let (name, passwd) = match o.split_once(':') {
            None => {
                let (r, pw) = ui::read_pw_string(4096 - 1, &format!("Enter {o}: "), false);
                if r < 0 {
                    if r == -2 {
                        eprintf!("user abort\n");
                    } else {
                        eprintf!("entry failed\n");
                    }
                    return 1;
                }
                (o.as_str(), String::from_utf8_lossy(&pw).into_owned())
            }
            Some((name, src)) => {
                let Some((Some(pw), _)) = app_passwd(Some(src), None) else {
                    eprintf!("failed to get '{name}'\n");
                    return 1;
                };
                (name, pw.as_str().to_owned())
            }
        };
        if pctx.borrow().ctrl_str(name, &passwd) <= 0 {
            eprintf!("{prog}: Can't set parameter \"{name}\":\n");
            return 1;
        }
    }
    if sigfile.is_some() && pkey_op != EVP_PKEY_OP_VERIFY {
        eprintf!("{prog}: Signature file specified for non verify\n");
        return 1;
    }
    if sigfile.is_none() && pkey_op == EVP_PKEY_OP_VERIFY {
        eprintf!("{prog}: No signature file specified for verify\n");
        return 1;
    }
    let mut filesize: i64 = -1;
    let mut input = None;
    if pkey_op != EVP_PKEY_OP_DERIVE && pkey_op != EVP_PKEY_OP_ENCAPSULATE {
        input = bio_open_default(infile.as_deref(), 'r', format::BINARY);
        if let Some(f) = &infile
            && let Ok(md) = std::fs::metadata(f)
            && md.len() <= u64::try_from(i32::MAX).unwrap_or(0)
        {
            filesize = i64::try_from(md.len()).unwrap_or(-1);
        }
        if input.is_none() {
            return 1;
        }
    }
    let out = if pkey_op == EVP_PKEY_OP_DECAPSULATE && outfile.is_some() {
        if secoutfile.is_some() {
            eprintf!(
                "{prog}: Decapsulation produces only a shared secret and no output. The '-out' option is not applicable.\n"
            );
            return 1;
        }
        // Upstream passes 'w' as the format and FORMAT_BINARY as `private`.
        bio_open_owner(outfile.as_deref(), i32::from(b'w'), true)
    } else {
        bio_open_default(outfile.as_deref(), 'w', format::BINARY)
    };
    let Some(out) = out else {
        return 1;
    };
    let mut secout = None;
    if pkey_op == EVP_PKEY_OP_ENCAPSULATE || pkey_op == EVP_PKEY_OP_DECAPSULATE {
        if secoutfile.is_none() && pkey_op == EVP_PKEY_OP_ENCAPSULATE {
            eprintf!("KEM-based shared-secret derivation requires the '-secret <file>' option\n");
            return 1;
        }
        if secoutfile.is_some() {
            secout = bio_open_owner(secoutfile.as_deref(), i32::from(b'w'), true);
            if secout.is_none() {
                return 1;
            }
        }
    }
    let mut sig = Vec::new();
    if let Some(sf) = &sigfile {
        let Some(sigbio) = Bio::new_file(sf, "rb") else {
            eprintf!("Can't open signature file {sf}\n");
            return 1;
        };
        let Some(s) = bio_to_mem(16 * 1024 * 1024, &sigbio) else {
            eprintf!("Error reading signature data\n");
            return 1;
        };
        sig = s;
    }
    let mut buf_in = Vec::new();
    if let Some(i) = &input
        && !rawin
    {
        let Some(b) = bio_to_mem(0, i) else {
            eprintf!("Error reading input Data\n");
            return 1;
        };
        buf_in = b;
        if rev {
            buf_in.reverse();
        }
    }
    if !rawin && (pkey_op == EVP_PKEY_OP_SIGN || pkey_op == EVP_PKEY_OP_VERIFY) {
        let max = usize::try_from(EVP_MAX_MD_SIZE).unwrap_or(0);
        if buf_in.len() > max {
            eprintf!(
                "Error: The non-raw input data length {} is too long - max supported hashed size is {EVP_MAX_MD_SIZE}\n",
                buf_in.len()
            );
            return 1;
        }
    }
    if pkey_op == EVP_PKEY_OP_VERIFY {
        let rv = match (&ctx, &input, &pkey) {
            (Ctx::Md(m), Some(i), Some(k)) => do_raw_keyop(pkey_op, m, k, i, filesize, &sig).0,
            _ => pctx.verify(&sig, &buf_in),
        };
        if rv == 1 {
            let _ = out.write_all(b"Signature Verified Successfully\n");
            return 0;
        }
        let _ = out.write_all(b"Signature Verification Failure\n");
        return 1;
    }
    let mut buf_out = Vec::new();
    let mut secret = Vec::new();
    let rv;
    if let (Ctx::Md(m), Some(i), Some(k)) = (&ctx, &input, &pkey) {
        let (r, o) = do_raw_keyop(pkey_op, m, k, i, filesize, &[]);
        rv = r;
        buf_out = o;
    } else {
        let (mut outlen, mut secretlen) = (0usize, 0usize);
        let mut r = if kdflen != 0 {
            outlen = usize::try_from(kdflen).unwrap_or(0);
            1
        } else {
            do_keyop(
                pctx,
                pkey_op,
                None,
                &mut outlen,
                &buf_in,
                None,
                &mut secretlen,
            )
        };
        let kem = pkey_op == EVP_PKEY_OP_ENCAPSULATE || pkey_op == EVP_PKEY_OP_DECAPSULATE;
        if r > 0 && (secretlen > 0 || !kem) && (outlen > 0 || pkey_op == EVP_PKEY_OP_DECAPSULATE) {
            buf_out = vec![0u8; outlen];
            secret = vec![0u8; secretlen];
            let o = (outlen > 0).then_some(buf_out.as_mut_slice());
            let s = (secretlen > 0).then_some(secret.as_mut_slice());
            r = do_keyop(pctx, pkey_op, o, &mut outlen, &buf_in, s, &mut secretlen);
            buf_out.truncate(outlen);
            secret.truncate(secretlen);
        }
        rv = r;
    }
    if rv <= 0 {
        if pkey_op != EVP_PKEY_OP_DERIVE {
            eprintf!("Public Key operation error\n");
        } else {
            eprintf!("Key derivation failed\n");
        }
        return 1;
    }
    if asn1parse {
        if out.asn1_parse_dump(&buf_out, 1, -1) == 0 {
            io::print_errors();
        }
    } else if hexdump {
        out.dump(&buf_out);
    } else {
        out.write(&buf_out);
    }
    if !secret.is_empty() {
        secout.as_ref().unwrap_or(&out).write(&secret);
    }
    0
}
