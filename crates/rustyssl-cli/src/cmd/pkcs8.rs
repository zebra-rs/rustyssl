//! `openssl pkcs8` (`apps/pkcs8.c`).

use rustyssl_ossl::abi::{EVP_PBE_TYPE_PRF, PKCS12_DEFAULT_ITER};
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::obj;
use rustyssl_ossl::pkcs8::{self, Algor, EncryptedKey, P8Info};
use rustyssl_ossl::ui;

use crate::generated::options::pkcs8::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_default, bio_open_owner, load_key};
use crate::lib::opt::opt_cipher;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

/// `APP_PASS_LEN` of `apps.h`.
const APP_PASS_LEN: usize = 1024;

/// A password as C's `strlen` sees it: up to its first NUL.
fn c_str_bytes(b: &[u8]) -> Vec<u8> {
    b.split(|&c| c == 0).next().unwrap_or_default().to_vec()
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut e = None;
    let (mut infile, mut outfile, mut ciphername) = (None, None, None);
    let (mut passinarg, mut passoutarg) = (None, None);
    let mut cipher: Option<Cipher> = None;
    let (mut nocrypt, mut topk8, mut traditional) = (false, false, false);
    let mut iter = PKCS12_DEFAULT_ITER;
    let (mut informat, mut outformat) = (format::UNDEF, format::PEM);
    let mut pbe_nid = -1;
    let (mut scrypt_n, mut scrypt_r, mut scrypt_p) = (0i64, 0i64, 0i64);
    let mut saltlen = 0;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::TOPK8 => topk8 = true,
            Opt::NOITER => iter = 1,
            Opt::NOCRYPT => nocrypt = true,
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
            Opt::TRADITIONAL => traditional = true,
            Opt::V2 => ciphername = Some(p.arg().to_owned()),
            Opt::V1 => {
                pbe_nid = obj::txt2nid(p.arg());
                if pbe_nid == 0 {
                    eprintf!("{prog}: Unknown PBE algorithm {}\n", p.arg());
                    return usage();
                }
            }
            Opt::V2PRF => {
                pbe_nid = obj::txt2nid(p.arg());
                if !pkcs8::pbe_find(EVP_PBE_TYPE_PRF, pbe_nid) {
                    eprintf!("{prog}: Unknown PRF algorithm {}\n", p.arg());
                    return usage();
                }
                if cipher.is_none() {
                    cipher = Cipher::aes_256_cbc();
                }
            }
            Opt::ITER => iter = p.int_arg(),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::SCRYPT => {
                (scrypt_n, scrypt_r, scrypt_p) = (16384, 8, 1);
                if cipher.is_none() {
                    cipher = Cipher::aes_256_cbc();
                }
            }
            Opt::SCRYPT_N => match opt::long(p.arg()) {
                Some(v) if v > 0 => scrypt_n = v,
                _ => return usage(),
            },
            Opt::SCRYPT_R => match opt::long(p.arg()) {
                Some(v) if v > 0 => scrypt_r = v,
                _ => return usage(),
            },
            Opt::SCRYPT_P => match opt::long(p.arg()) {
                Some(v) if v > 0 => scrypt_p = v,
                _ => return usage(),
            },
            Opt::SALTLEN => match opt::int(p.arg()) {
                Some(v) => saltlen = v,
                None => return usage(),
            },
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    let private = true;
    if !app_rand::load() {
        return 1;
    }
    if ciphername.is_some() {
        match opt_cipher(ciphername.as_deref()) {
            Ok(c) => cipher = c,
            Err(()) => return usage(),
        }
    }
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    if pbe_nid == -1 && cipher.is_none() {
        cipher = Cipher::aes_256_cbc();
    }
    let in_fmt = if informat == format::UNDEF {
        format::PEM
    } else {
        informat
    };
    let Some(input) = bio_open_default(infile.as_deref(), 'r', in_fmt) else {
        return 1;
    };
    if topk8 {
        let pin = passin.as_ref().map(|p| p.as_str());
        let Some(pkey) = load_key(
            infile.as_deref(),
            informat,
            true,
            pin,
            e.as_ref(),
            Some("key"),
        ) else {
            return 1;
        };
        let Some(p8inf) = P8Info::from_pkey(&pkey) else {
            eprintf!("Error converting key\n");
            io::print_errors();
            return 1;
        };
        let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
            return 1;
        };
        if nocrypt {
            if outformat == format::PEM {
                p8inf.write_pem(&out);
            } else if outformat == format::ASN1 {
                p8inf.write_der(&out);
            } else {
                eprintf!("Bad format specified for key\n");
                return 1;
            }
        } else {
            let to_u64 = |v: i64| u64::try_from(v).unwrap_or(0);
            let pbe = match &cipher {
                Some(c) if scrypt_n != 0 && scrypt_r != 0 && scrypt_p != 0 => Algor::pbe2_scrypt(
                    c,
                    saltlen,
                    to_u64(scrypt_n),
                    to_u64(scrypt_r),
                    to_u64(scrypt_p),
                ),
                Some(c) => Algor::pbe2_iv(c, iter, saltlen, pbe_nid),
                None => Algor::pbe1(pbe_nid, iter, saltlen),
            };
            let Some(pbe) = pbe else {
                eprintf!("Error setting PBE algorithm\n");
                io::print_errors();
                return 1;
            };
            let p8pass: Vec<u8> = match &passout {
                Some(pw) => c_str_bytes(pw.as_bytes()),
                None => {
                    let (r, pw) =
                        ui::read_pw_string(APP_PASS_LEN, "Enter Encryption Password:", true);
                    if r != 0 {
                        return 1;
                    }
                    pw
                }
            };
            let Some(p8) = EncryptedKey::encrypt(&p8pass, &p8inf, pbe) else {
                eprintf!("Error encrypting key\n");
                io::print_errors();
                return 1;
            };
            if outformat == format::PEM {
                p8.write_pem(&out);
            } else if outformat == format::ASN1 {
                p8.write_der(&out);
            } else {
                eprintf!("Bad format specified for key\n");
                return 1;
            }
        }
        return 0;
    }

    let p8inf = if nocrypt {
        if informat == format::PEM || informat == format::UNDEF {
            P8Info::read_pem(&input)
        } else if informat == format::ASN1 {
            P8Info::read_der(&input)
        } else {
            eprintf!("Bad format specified for key\n");
            return 1;
        }
    } else {
        let p8 = if informat == format::PEM || informat == format::UNDEF {
            EncryptedKey::read_pem(&input)
        } else if informat == format::ASN1 {
            EncryptedKey::read_der(&input)
        } else {
            eprintf!("Bad format specified for key\n");
            return 1;
        };
        let Some(p8) = p8 else {
            eprintf!("Error reading key\n");
            io::print_errors();
            return 1;
        };
        let p8pass: Vec<u8> = match &passin {
            Some(pw) => c_str_bytes(pw.as_bytes()),
            None => {
                let (r, pw) = ui::read_pw_string(APP_PASS_LEN, "Enter Password:", false);
                if r != 0 {
                    eprintf!("Can't read Password\n");
                    return 1;
                }
                pw
            }
        };
        p8.decrypt(&p8pass)
    };
    let Some(p8inf) = p8inf else {
        eprintf!("Error decrypting key\n");
        io::print_errors();
        return 1;
    };
    let Some(pkey) = p8inf.to_pkey() else {
        eprintf!("Error converting key\n");
        io::print_errors();
        return 1;
    };
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    let pout = passout.as_ref().map(|p| p.as_str());
    if outformat == format::PEM {
        pkey.write_pem_private(&out, None, pout, traditional);
    } else if outformat == format::ASN1 {
        pkey.write_der_private(&out);
    } else {
        eprintf!("Bad format specified for key\n");
        return 1;
    }
    0
}
