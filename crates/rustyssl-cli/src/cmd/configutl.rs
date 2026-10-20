//! `openssl configutl` (`apps/configutl.c`): a configuration file, linearized and expanded.

use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::crypto;

use crate::generated::options::configutl::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, format};

/// `print_escaped_value`: the value escaped for the configuration file format.
fn escaped_value(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let last = value.len().saturating_sub(1);
    for (i, &c) in value.iter().enumerate() {
        match c {
            b'"' | b'\'' | b'#' | b'\\' | b'$' => out.extend_from_slice(&[b'\\', c]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            0x08 => out.extend_from_slice(b"\\b"),
            b'\t' => out.extend_from_slice(b"\\t"),
            // A leading or trailing space is quoted.
            b' ' if i == 0 || i == last => out.extend_from_slice(b"\" \""),
            _ => out.push(c),
        }
    }
    out
}

/// `print_section`: every value of the section.
fn print_section(out: &mut Vec<u8>, cnf: &Conf, section: &[u8]) {
    for (name, value) in cnf.get_section_bytes(section) {
        out.extend_from_slice(&name);
        out.extend_from_slice(b" = ");
        out.extend_from_slice(&escaped_value(&value));
        out.push(b'\n');
    }
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    io::print_errors();
    ret
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let mut configfile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut no_header = false;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::NOHEADER => no_header = true,
            Opt::CONFIG => configfile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ERR => {
                eprintf!("{prog}: Use -help for summary.\n");
                return 1;
            }
        }
    }

    let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::TEXT) else {
        return 1;
    };
    let Some(configfile) = configfile.or_else(crypto::default_config_file) else {
        return 1;
    };
    let Some(cnf) = Conf::new(None) else {
        return 1;
    };
    let (ok, eline) = cnf.load(&configfile);
    if ok == 0 {
        eprintf!("Error on line {} of configuration file\n", eline + 1);
        return 1;
    }
    let Some(sections) = cnf.section_names() else {
        return 1;
    };

    let mut text = Vec::new();
    if !no_header {
        text.extend_from_slice(
            format!("# This configuration file was linearized and expanded from {configfile}\n")
                .as_bytes(),
        );
    }
    let default_idx = sections.iter().position(|s| s == b"default");
    if default_idx.is_some() {
        print_section(&mut text, &cnf, b"default");
    }
    for (idx, name) in sections.iter().enumerate() {
        if Some(idx) == default_idx {
            continue;
        }
        text.extend_from_slice(b"\n[");
        text.extend_from_slice(name);
        text.extend_from_slice(b"]\n");
        print_section(&mut text, &cnf, name);
    }
    let _ = out.write_all(&text);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escaped_value(b"plain value"), b"plain value");
        assert_eq!(escaped_value(b" a b "), b"\" \"a b\" \"");
        assert_eq!(escaped_value(b" "), b"\" \"");
        assert_eq!(escaped_value(b"a\"'#\\$b"), b"a\\\"\\'\\#\\\\\\$b");
        assert_eq!(escaped_value(b"\n\r\x08\t"), b"\\n\\r\\b\\t");
        assert_eq!(escaped_value(b""), b"");
    }
}
