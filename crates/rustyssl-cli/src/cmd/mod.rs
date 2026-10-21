//! The commands (`apps/<command>.c`), one module each.
//!
//! A command is ported when its module exists (`cmd/<command>.rs`, with `pub fn main(argv:
//! &[String]) -> i32`) and its line below is uncommented; `cargo xtask test-apps` then runs its
//! corpus, `tests/apps/<command>.txt`, with this binary. Every other command fails closed
//! ([`crate::unported`]). Each command fork uncomments only its own lines.

pub mod version;
// pub mod asn1parse;
// pub mod ca;
// pub mod ciphers;
// pub mod cmp;
// pub mod cms;
// pub mod configutl;
// pub mod crl;
// pub mod crl2pkcs7;
pub mod dgst;
// pub mod dhparam;
// pub mod dsa;
// pub mod dsaparam;
// pub mod ec;
// pub mod ecparam;
pub mod enc;
// pub mod engine;
pub mod errstr;
// pub mod fipsinstall;
// pub mod gendsa;
// pub mod genpkey;
// pub mod genrsa;
pub mod info;
// pub mod kdf;
// pub mod list;
// pub mod mac;
pub mod nseq;
// pub mod ocsp;
// pub mod passwd;
// pub mod pkcs12;
// pub mod pkcs7;
// pub mod pkcs8;
// pub mod pkey;
// pub mod pkeyparam;
// pub mod pkeyutl;
pub mod prime;
pub mod rand;
// pub mod rehash;
// pub mod req;
// pub mod rsa;
// pub mod rsautl;
// pub mod s_client;
// pub mod s_server;
// pub mod s_time;
// pub mod sess_id;
// pub mod skeyutl;
// pub mod smime;
// pub mod speed;
// pub mod spkac;
// pub mod srp;
// pub mod storeutl;
// pub mod ts;
// pub mod verify;
// pub mod x509;

/// The command's `main`, if it is ported.
pub fn find(name: &str) -> Option<fn(&[String]) -> i32> {
    Some(match name {
        "help" => crate::help_main,
        "version" => version::main,
        // "asn1parse" => asn1parse::main,
        // "ca" => ca::main,
        // "ciphers" => ciphers::main,
        // "cmp" => cmp::main,
        // "cms" => cms::main,
        // "configutl" => configutl::main,
        // "crl" => crl::main,
        // "crl2pkcs7" => crl2pkcs7::main,
        "dgst" => dgst::main,
        // "dhparam" => dhparam::main,
        // "dsa" => dsa::main,
        // "dsaparam" => dsaparam::main,
        // "ec" => ec::main,
        // "ecparam" => ecparam::main,
        "enc" => enc::main,
        // "engine" => engine::main,
        "errstr" => errstr::main,
        // "fipsinstall" => fipsinstall::main,
        // "gendsa" => gendsa::main,
        // "genpkey" => genpkey::main,
        // "genrsa" => genrsa::main,
        "info" => info::main,
        // "kdf" => kdf::main,
        // "list" => list::main,
        // "mac" => mac::main,
        "nseq" => nseq::main,
        // "ocsp" => ocsp::main,
        // "passwd" => passwd::main,
        // "pkcs12" => pkcs12::main,
        // "pkcs7" => pkcs7::main,
        // "pkcs8" => pkcs8::main,
        // "pkey" => pkey::main,
        // "pkeyparam" => pkeyparam::main,
        // "pkeyutl" => pkeyutl::main,
        "prime" => prime::main,
        "rand" => rand::main,
        // "rehash" => rehash::main,
        // "req" => req::main,
        // "rsa" => rsa::main,
        // "rsautl" => rsautl::main,
        // "s_client" => s_client::main,
        // "s_server" => s_server::main,
        // "s_time" => s_time::main,
        // "sess_id" => sess_id::main,
        // "skeyutl" => skeyutl::main,
        // "smime" => smime::main,
        // "speed" => speed::main,
        // "spkac" => spkac::main,
        // "srp" => srp::main,
        // "storeutl" => storeutl::main,
        // "ts" => ts::main,
        // "verify" => verify::main,
        // "x509" => x509::main,
        _ => return None,
    })
}
