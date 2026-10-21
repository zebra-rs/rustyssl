//! `apps.c`'s CA database and serial-number files, for `ca` and `x509` (and `ocsp`'s index):
//! `load_serial`, `save_serial`, `rotate_serial`, `rand_serial`, and the index (`load_index`,
//! `index_index`, `save_index`, `rotate_index`), with upstream's exact messages.

use std::io::Write;

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY};
use rustyssl_ossl::x509::{Bn, Integer};

use super::io;
use super::opt::eprintf;

/// `SERIAL_RAND_BITS` of `apps.h`.
pub const SERIAL_RAND_BITS: i32 = 159;

/// `BSIZE` of `apps.c`: the longest file name the helpers make, plus one.
const BSIZE: usize = 256;

/// `perror(s)`: `s: <the last system error>`.
pub fn perror(s: &str) {
    let e = std::io::Error::last_os_error();
    let reason = super::apps::strerror(e.raw_os_error().unwrap_or(0));
    let _ = writeln!(io::err(), "{s}: {reason}");
}

/// `rand_serial(b, ai)`: a random serial number of [`SERIAL_RAND_BITS`] bits.
pub fn rand_serial() -> Option<(Bn, Integer)> {
    let b = Bn::new()?;
    if !b.rand(SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) {
        return None;
    }
    let ai = Integer::from_bn(&b)?;
    Some((b, ai))
}

/// `load_serial(serialfile, &exists, create, &retai)`: the serial number in the file (or, if
/// it doesn't exist and `create`, a random one); whether the file exists; and the number as
/// read. `None` on failure (the errors printed).
pub fn load_serial(serialfile: &str, create: bool) -> (Option<(Bn, Integer)>, bool) {
    let input = Bio::new_file(serialfile, "r");
    let exists = input.is_some();
    let ret = match input {
        None => {
            if !create {
                perror(serialfile);
                None
            } else {
                rustyssl_ossl::err::clear();
                match rand_serial() {
                    Some(r) => Some(r),
                    None => {
                        eprintf!("Error creating random number to store in {serialfile}\n");
                        None
                    }
                }
            }
        }
        Some(input) => match Integer::read_a2i(&input) {
            None => {
                eprintf!("Unable to load number from {serialfile}\n");
                None
            }
            Some(ai) => match ai.to_bn() {
                Some(bn) => Some((bn, ai)),
                None => {
                    eprintf!("Error converting number from bin to BIGNUM\n");
                    None
                }
            },
        },
    };
    if ret.is_none() {
        io::print_errors();
    }
    (ret, exists)
}

/// `save_serial(serialfile, suffix, serial, &retai)`: writes the serial number (in hex, as
/// `i2a_ASN1_INTEGER`) to `serialfile` or `serialfile.suffix`.
pub fn save_serial(serialfile: &str, suffix: Option<&str>, serial: &Bn) -> Option<Integer> {
    let ret = (|| {
        let j = match suffix {
            None => serialfile.len(),
            Some(s) => serialfile.len() + s.len() + 1,
        };
        if j >= BSIZE {
            eprintf!("File name too long\n");
            return None;
        }
        let name = match suffix {
            None => serialfile.to_owned(),
            Some(s) => format!("{serialfile}.{s}"),
        };
        let out = Bio::new_file(&name, "w")?;
        let Some(ai) = Integer::from_bn(serial) else {
            eprintf!("error converting serial to ASN.1 format\n");
            return None;
        };
        ai.i2a(&out);
        let _ = out.write_all(b"\n");
        Some(ai)
    })();
    if ret.is_none() {
        io::print_errors();
    }
    ret
}

/// `rename(from, to)`, as C reports it: the error, if any.
fn rename(from: &str, to: &str) -> Option<std::io::Error> {
    std::fs::rename(from, to).err()
}

/// Whether a failed `rename` is one `rotate_*` tolerates (`ENOENT`, `ENOTDIR`).
fn tolerated(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// `perror("reason")` for an error already taken.
fn reason(e: &std::io::Error) {
    let r = super::apps::strerror(e.raw_os_error().unwrap_or(0));
    let _ = writeln!(io::err(), "reason: {r}");
}

/// `rotate_serial(serialfile, new_suffix, old_suffix)`.
pub fn rotate_serial(serialfile: &str, new_suffix: &str, old_suffix: &str) -> bool {
    let ok = (|| {
        let j = (serialfile.len() + old_suffix.len()).max(serialfile.len() + new_suffix.len());
        if j + 1 >= BSIZE {
            eprintf!("File name too long\n");
            return false;
        }
        let new = format!("{serialfile}.{new_suffix}");
        let old = format!("{serialfile}.{old_suffix}");
        if let Some(e) = rename(serialfile, &old)
            && !tolerated(&e)
        {
            eprintf!("Unable to rename {serialfile} to {old}\n");
            reason(&e);
            return false;
        }
        if let Some(e) = rename(&new, serialfile) {
            eprintf!("Unable to rename {new} to {serialfile}\n");
            reason(&e);
            let _ = rename(&old, serialfile);
            return false;
        }
        true
    })();
    if !ok {
        io::print_errors();
    }
    ok
}
