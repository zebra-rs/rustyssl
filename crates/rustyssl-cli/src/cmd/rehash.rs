//! `openssl rehash` (`apps/rehash.c`): the `<hash>.<n>` and `<hash>.r<n>` symbolic links of a
//! certificate directory, as `X509_LOOKUP_hash_dir` finds certificates and CRLs.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use rustyssl_ossl::evp::Md;
use rustyssl_ossl::x509::{self, InfoKind, InfoStack};
use rustyssl_ossl::{Bio, sys};

use crate::generated::options::rehash::{OPTIONS, Opt};
use crate::lib::apps::strerror;
use crate::lib::opt::{self, Parser, eprintf, prog};
use crate::lib::{app_libctx, io};

/// The most links one hash may need.
const MAX_COLLISIONS: u16 = 256;
/// `PATH_MAX`: the longest link target read.
const PATH_MAX: usize = 4096;
/// The hash table's size.
const TABLE_SIZE: u32 = 257;
/// Each type's link suffix (`<hash>.<suffix><n>`).
const SUFFIXES: [&str; 2] = ["", "r"];
/// The file extensions looked at.
const EXTENSIONS: [&str; 4] = ["pem", "crt", "cer", "crl"];

const TYPE_CERT: usize = 0;
const TYPE_CRL: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hash {
    Old,
    New,
    Both,
}

struct Entry {
    filename: Vec<u8>,
    old_id: u16,
    need_symlink: bool,
    digest: [u8; 64],
}

struct Bucket {
    kind: usize,
    hash: u32,
    num_needed: u16,
    entries: Vec<Entry>,
}

struct Rehash {
    md: Md,
    mdsize: usize,
    remove_links: bool,
    verbose: bool,
    /// Each slot's buckets, newest first.
    table: Vec<Vec<Bucket>>,
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn last_errno(e: &std::io::Error) -> String {
    strerror(e.raw_os_error().unwrap_or(0))
}

/// `strtoul(s, &end, 10)`: the value (saturated, negated when signed) and whether all of `s`
/// was used (`*end == '\0'`; true for no digits only when `s` is empty).
fn strtoul_all(s: &[u8]) -> (u64, bool) {
    let mut i = 0;
    while s
        .get(i)
        .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c @ (b'+' | b'-')) = s.get(i) {
        neg = c == b'-';
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while let Some(d) = s.get(i).filter(|c| c.is_ascii_digit()) {
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
        {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        // No digits: the end is the start.
        return (0, s.is_empty());
    }
    let v = if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    (v, i == s.len())
}

/// The low 16 bits, as C converts to `unsigned short`.
fn low16(v: u64) -> u16 {
    u16::try_from(v & 0xffff).unwrap_or(u16::MAX)
}

impl Rehash {
    /// `add_entry`: the number of errors (an overflowing hash).
    fn add_entry(
        &mut self,
        kind: usize,
        hash: u32,
        filename: &[u8],
        digest: Option<&[u8]>,
        need_symlink: bool,
        old_id: u16,
    ) -> i32 {
        let kind32 = u32::try_from(kind).unwrap_or(0);
        let ndx = usize::try_from(kind32.wrapping_add(hash) % TABLE_SIZE).unwrap_or(0);
        let mdsize = self.mdsize;
        let Some(slot) = self.table.get_mut(ndx) else {
            return 0;
        };
        let at = match slot.iter().position(|b| b.kind == kind && b.hash == hash) {
            Some(i) => i,
            None => {
                slot.insert(
                    0,
                    Bucket {
                        kind,
                        hash,
                        num_needed: 0,
                        entries: Vec::new(),
                    },
                );
                0
            }
        };
        let Some(bp) = slot.get_mut(at) else {
            return 0;
        };
        let mut found = None;
        for (i, ep) in bp.entries.iter().enumerate() {
            if let Some(d) = digest
                && d.get(..mdsize) == ep.digest.get(..mdsize)
            {
                eprintf!(
                    "{}: warning: skipping duplicate {} in {}\n",
                    prog(),
                    if kind == TYPE_CERT {
                        "certificate"
                    } else {
                        "CRL"
                    },
                    show(filename)
                );
                return 0;
            }
            if ep.filename == filename {
                found = Some(i);
                if digest.is_none() {
                    break;
                }
            }
        }
        let i = match found {
            Some(i) => i,
            None => {
                if bp.num_needed >= MAX_COLLISIONS {
                    eprintf!(
                        "{}: error: hash table overflow for {}\n",
                        prog(),
                        show(filename)
                    );
                    return 1;
                }
                bp.entries.push(Entry {
                    filename: filename.to_vec(),
                    old_id: u16::MAX,
                    need_symlink: false,
                    digest: [0; 64],
                });
                bp.entries.len() - 1
            }
        };
        let Some(ep) = bp.entries.get_mut(i) else {
            return 0;
        };
        if old_id < ep.old_id {
            ep.old_id = old_id;
        }
        if need_symlink && !ep.need_symlink {
            ep.need_symlink = true;
            bp.num_needed += 1;
            if let (Some(dst), Some(src)) = (
                ep.digest.get_mut(..mdsize),
                digest.and_then(|d| d.get(..mdsize)),
            ) {
                dst.copy_from_slice(src);
            }
        }
        0
    }

    /// `handle_symlink`: 0 when `filename` is a hash link (recorded), else what `add_entry`
    /// returned or -1 (not a hash link).
    fn handle_symlink(&mut self, filename: &[u8], fullpath: &std::path::Path) -> i32 {
        let mut hash: u32 = 0;
        for i in 0..8 {
            let Some(d) = filename.get(i).and_then(|c| char::from(*c).to_digit(16)) else {
                return -1;
            };
            hash = (hash << 4) + d;
        }
        if filename.get(8) != Some(&b'.') {
            return -1;
        }
        let rest = filename.get(9..).unwrap_or_default();
        let kind = if rest.first().is_some_and(|c| c.eq_ignore_ascii_case(&b'r')) {
            TYPE_CRL
        } else {
            TYPE_CERT
        };
        let skip = SUFFIXES.get(kind).map_or(0, |s| s.len());
        let digits = rest.get(skip..).unwrap_or_default();
        let (id, all) = strtoul_all(digits);
        if !all {
            return -1;
        }
        let Ok(target) = std::fs::read_link(fullpath) else {
            return -1;
        };
        let target = target.as_os_str().as_bytes();
        if target.len() >= PATH_MAX {
            return -1;
        }
        // C stores the id in an int, then an unsigned short.
        self.add_entry(kind, hash, target, None, false, low16(id))
    }

    /// `do_file`: the number of errors.
    fn do_file(&mut self, filename: &[u8], fullpath: &str, h: Hash) -> i32 {
        // Only the recognized extensions.
        let Some(dot) = filename.iter().rposition(|&c| c == b'.') else {
            return 0;
        };
        let ext = filename.get(dot + 1..).unwrap_or_default();
        if !EXTENSIONS
            .iter()
            .any(|e| e.as_bytes().eq_ignore_ascii_case(ext))
        {
            return 0;
        }
        let Some(b) = Bio::new_file(fullpath, "r") else {
            eprintf!(
                "{}: error: skipping {}, cannot open file\n",
                prog(),
                show(filename)
            );
            return 1;
        };
        let inf = InfoStack::read_pem(&b);
        drop(b);
        let Some(inf) = inf else {
            return 0;
        };
        if inf.len() != 1 {
            // Not an error.
            eprintf!(
                "{}: warning: skipping {}, it does not contain exactly one certificate or CRL\n",
                prog(),
                show(filename)
            );
            return 0;
        }
        let kind = match inf.kind(0) {
            InfoKind::Cert => TYPE_CERT,
            InfoKind::Crl => TYPE_CRL,
            InfoKind::Other => return 1,
        };
        let Some(digest) = inf.digest(0, &self.md) else {
            eprintf!("out of memory\n");
            return 1;
        };
        let mut errs = 0;
        if h == Hash::New || h == Hash::Both {
            let libctx = app_libctx::libctx();
            let propq = app_libctx::propq();
            match inf.name_hash(0, libctx.as_deref(), propq.as_deref()) {
                None => return errs,
                Some(Some(v)) => {
                    let v = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
                    errs += self.add_entry(kind, v, filename, Some(&digest), true, u16::MAX);
                }
                Some(None) => {
                    eprintf!("{}: error calculating SHA1 hash value\n", prog());
                    errs += 1;
                }
            }
        }
        if (h == Hash::Old || h == Hash::Both)
            && let Some(v) = inf.name_hash_old(0)
        {
            let v = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
            errs += self.add_entry(kind, v, filename, Some(&digest), true, u16::MAX);
        }
        errs
    }

    /// `do_dir`: the number of errors.
    fn do_dir(&mut self, dirname: &str, h: Hash) -> i32 {
        if !sys::writable(dirname) {
            eprintf!("Skipping {dirname}, can't write\n");
            return 1;
        }
        let pathsep = if !dirname.is_empty() && !dirname.ends_with('/') {
            "/"
        } else {
            ""
        };
        let mut out = io::out();
        if self.verbose {
            let _ = writeln!(out, "Doing {dirname}");
        }
        let mut files: Vec<Vec<u8>> = match std::fs::read_dir(dirname) {
            Ok(d) => d
                .filter_map(Result::ok)
                .map(|e| e.file_name().as_bytes().to_vec())
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        let mut errs = 0;
        for filename in &files {
            let path = format!("{dirname}{pathsep}{}", show(filename));
            let full = std::path::Path::new(dirname).join(std::ffi::OsStr::from_bytes(filename));
            let Ok(st) = std::fs::symlink_metadata(&full) else {
                continue;
            };
            if st.file_type().is_symlink() && self.handle_symlink(filename, &full) == 0 {
                continue;
            }
            errs += self.do_file(filename, &path, h);
        }

        let table = std::mem::replace(&mut self.table, empty_table());
        for slot in table {
            for bp in slot {
                let mut idmask = [false; MAX_COLLISIONS as usize + 8];
                for ep in &bp.entries {
                    if ep.old_id < bp.num_needed
                        && let Some(b) = idmask.get_mut(usize::from(ep.old_id))
                    {
                        *b = true;
                    }
                }
                let suffix = SUFFIXES.get(bp.kind).copied().unwrap_or_default();
                let mut nextid = 0usize;
                for ep in &bp.entries {
                    if ep.old_id < bp.num_needed {
                        // The link exists and is used as it is.
                        if self.verbose {
                            let _ = writeln!(
                                out,
                                "link {} -> {:08x}.{suffix}{}",
                                show(&ep.filename),
                                bp.hash,
                                ep.old_id
                            );
                        }
                    } else if ep.need_symlink {
                        // A new link (which may replace something).
                        while idmask.get(nextid).copied().unwrap_or(false) {
                            nextid += 1;
                        }
                        let name = format!("{:08x}.{suffix}{nextid}", bp.hash);
                        let link = format!("{dirname}{pathsep}{name}");
                        if self.verbose {
                            let _ = writeln!(out, "link {} -> {name}", show(&ep.filename));
                        }
                        if let Err(e) = std::fs::remove_file(&link)
                            && e.kind() != std::io::ErrorKind::NotFound
                        {
                            eprintf!("{}: Can't unlink {link}, {}\n", prog(), last_errno(&e));
                            errs += 1;
                        }
                        let target = std::ffi::OsStr::from_bytes(&ep.filename);
                        if let Err(e) = std::os::unix::fs::symlink(target, &link) {
                            eprintf!(
                                "{}: Can't symlink {}, {}\n",
                                prog(),
                                show(&ep.filename),
                                last_errno(&e)
                            );
                            errs += 1;
                        }
                        if let Some(b) = idmask.get_mut(nextid) {
                            *b = true;
                        }
                    } else if self.remove_links {
                        // A link to delete.
                        let name = format!("{:08x}.{suffix}{}", bp.hash, ep.old_id);
                        let link = format!("{dirname}{pathsep}{name}");
                        if self.verbose {
                            let _ = writeln!(out, "unlink {name}");
                        }
                        if let Err(e) = std::fs::remove_file(&link)
                            && e.kind() != std::io::ErrorKind::NotFound
                        {
                            eprintf!("{}: Can't unlink {link}, {}\n", prog(), last_errno(&e));
                            errs += 1;
                        }
                    }
                }
            }
        }
        errs
    }
}

fn empty_table() -> Vec<Vec<Bucket>> {
    (0..TABLE_SIZE).map(|_| Vec::new()).collect()
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let mut h = Hash::New;
    let (mut remove_links, mut verbose) = (true, false);
    loop {
        match p.next() {
            Opt::EOF => break,
            // Upstream's exit status is the error count, still 0 here.
            Opt::ERR => {
                eprintf!("{prog}: Use -help for summary.\n");
                return 0;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::COMPAT => h = Hash::Both,
            Opt::OLD => h = Hash::Old,
            Opt::N => remove_links = false,
            Opt::VERBOSE => verbose = true,
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 0;
                }
            }
        }
    }
    let dirs = p.rest().to_vec();
    let Some(md) = Md::sha1() else {
        return 0;
    };
    let mdsize = usize::try_from(md.size()).unwrap_or(0);
    if mdsize == 0 || mdsize > 64 {
        return 0;
    }
    let mut r = Rehash {
        md,
        mdsize,
        remove_links,
        verbose,
        table: empty_table(),
    };
    let mut errs = 0;
    if !dirs.is_empty() {
        for d in &dirs {
            errs += r.do_dir(d, h);
        }
    } else if let Some(env) = std::env::var_os(x509::default_cert_dir_env()) {
        let env = env.to_string_lossy().into_owned();
        // strtok: empty fields are skipped.
        for d in env.split(':').filter(|d| !d.is_empty()) {
            errs += r.do_dir(d, h);
        }
    } else {
        errs += r.do_dir(&x509::default_cert_dir(), h);
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::strtoul_all;

    #[test]
    fn strtoul_like_c() {
        assert_eq!(strtoul_all(b"0"), (0, true));
        assert_eq!(strtoul_all(b""), (0, true));
        assert_eq!(strtoul_all(b"12x"), (12, false));
        assert_eq!(strtoul_all(b"x"), (0, false));
        assert_eq!(strtoul_all(b"-1"), (u64::MAX, true));
    }
}
