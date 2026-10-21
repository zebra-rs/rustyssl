//! `openssl asn1parse` (`apps/asn1parse.c`).

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{V_ASN1_BOOLEAN, V_ASN1_NULL, V_ASN1_OBJECT};
use rustyssl_ossl::asn1::{self, Item, Type};

use crate::generated::options::asn1parse::{OPTIONS, Opt};
use crate::lib::apps::{app_load_config, bio_open_default};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

/// `strtol(s, NULL, 0)` of a value the parser already checked as an int.
fn number(s: &str) -> i64 {
    opt::strtol(s).unwrap_or(0)
}

/// `do_generate`: the DER of `-genstr`, or of `-genconf`'s `asn1` (or `-genstr` in its
/// context).
fn do_generate(genstr: Option<&str>, genconf: Option<&str>) -> Option<Vec<u8>> {
    let mut cnf = None;
    let mut genstr = genstr.map(str::to_owned);
    if let Some(file) = genconf {
        let c = app_load_config(Some(file))?;
        if genstr.is_none() {
            genstr = c.get_string(Some("default"), "asn1");
        }
        if genstr.is_none() {
            eprintf!("Can't find 'asn1' in '{file}'\n");
            return None;
        }
        cnf = Some(c);
    }
    Type::generate_der(genstr.as_deref().unwrap_or_default(), cnf.as_ref())
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
    let (mut indent, mut noout) = (false, false);
    let mut dump = 0;
    let mut informat = format::PEM;
    let mut offset: i64 = 0;
    let mut length: u64 = 0;
    let (mut infile, mut oidfile, mut derfile) = (None, None, None);
    let (mut genstr, mut genconf) = (None, None);
    let mut osk: Vec<String> = Vec::new();
    let mut it = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::ASN1) {
                Some(f) => informat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => derfile = Some(p.arg().to_owned()),
            Opt::INDENT => indent = true,
            Opt::NOOUT => noout = true,
            Opt::OID => oidfile = Some(p.arg().to_owned()),
            Opt::OFFSET => offset = number(p.arg()),
            Opt::LENGTH => length = u64::try_from(number(p.arg())).unwrap_or(0),
            Opt::DUMP => dump = -1,
            Opt::DLIMIT => dump = i32::try_from(number(p.arg())).unwrap_or(0),
            Opt::STRPARSE => osk.push(p.arg().to_owned()),
            Opt::GENSTR => genstr = Some(p.arg().to_owned()),
            Opt::GENCONF => genconf = Some(p.arg().to_owned()),
            // Accepted for backward compatibility.
            Opt::STRICTPEM => informat = format::PEM,
            Opt::ITEM => {
                let name = p.arg().to_owned();
                let Some(item) = Item::lookup(&name) else {
                    let mut text = format!("Unknown item name {name}\nSupported types:\n");
                    let mut i = 0;
                    while let Some(item) = Item::get(i) {
                        text.push_str(&format!("    {}\n", item.sname()));
                        i += 1;
                    }
                    eprintf!("{text}");
                    return 1;
                };
                it = Some(item);
            }
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }

    if let Some(oidfile) = &oidfile {
        let Some(input) = bio_open_default(Some(oidfile), 'r', format::TEXT) else {
            return 1;
        };
        asn1::create_objects(&input);
    }
    let Some(input) = bio_open_default(infile.as_deref(), 'r', informat) else {
        return 1;
    };
    let derout = match &derfile {
        Some(f) => match bio_open_default(Some(f), 'w', format::ASN1) {
            Some(b) => Some(b),
            None => return 1,
        },
        None => None,
    };

    let data: Vec<u8> = if genconf.is_none() && genstr.is_none() && informat == format::PEM {
        let Some(block) = asn1::pem_read(&input) else {
            eprintf!("Error reading PEM file\n");
            io::print_errors();
            return 1;
        };
        block.data
    } else if genstr.is_some() || genconf.is_some() {
        match do_generate(genstr.as_deref(), genconf.as_deref()) {
            Some(d) => d,
            None => {
                io::print_errors();
                return 1;
            }
        }
    } else if informat == format::BASE64 {
        let Some(b64) = Bio::new_base64() else {
            return 1;
        };
        b64.push(input).read_to_end()
    } else {
        input.read_to_end()
    };

    // Each -strparse digs into the structure at that offset of the previous one.
    let mut s: &[u8] = &data;
    let mut owned;
    for arg in &osk {
        let j = number(arg);
        let in_range = usize::try_from(j).ok().filter(|j| *j > 0 && *j < s.len());
        let Some(j) = in_range else {
            eprintf!("'{arg}' is out of range\n");
            continue;
        };
        let rest = s.get(j..).unwrap_or_default();
        let Some(at) = Type::d2i(rest) else {
            eprintf!("Error parsing structure\n");
            io::print_errors();
            return 1;
        };
        let typ = at.kind();
        if typ == V_ASN1_OBJECT || typ == V_ASN1_BOOLEAN || typ == V_ASN1_NULL {
            eprintf!("Can't parse {} type\n", asn1::tag2str(typ));
            io::print_errors();
            return 1;
        }
        owned = at.string_data();
        s = &owned;
    }

    let num = s.len();
    let Some(off) = usize::try_from(offset).ok().filter(|o| *o < num) else {
        eprintf!("Error: offset out of range\n");
        return 1;
    };
    let num = num - off;
    let len = if length == 0 || length > num as u64 {
        num
    } else {
        usize::try_from(length).unwrap_or(num)
    };
    let part = s.get(off..off + len).unwrap_or_default();
    if let Some(derout) = &derout
        && usize::try_from(derout.write(part)) != Ok(len)
    {
        eprintf!("Error writing output\n");
        io::print_errors();
        return 1;
    }
    if !noout {
        let Some(out) = io::bio_out() else {
            return 1;
        };
        if let Some(it) = it {
            if !it.d2i_print(part, out) {
                eprintf!("Error parsing item {}\n", it.sname());
                io::print_errors();
                return 1;
            }
        } else if !asn1::parse_dump(out, part, indent, dump) {
            io::print_errors();
            return 1;
        }
    }
    0
}
