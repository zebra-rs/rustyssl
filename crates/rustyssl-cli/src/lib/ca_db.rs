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

/// The fields of a CA database row (`DB_*` of `apps.h`).
pub mod field {
    pub const TYPE: usize = 0;
    pub const EXP_DATE: usize = 1;
    pub const REV_DATE: usize = 2;
    pub const SERIAL: usize = 3;
    pub const FILE: usize = 4;
    pub const NAME: usize = 5;
    /// `DB_NUMBER`.
    pub const NUMBER: usize = 6;
}

/// `DB_TYPE_*` of `apps.h`.
pub mod db_type {
    pub const REV: u8 = b'R';
    pub const EXP: u8 = b'E';
    pub const VAL: u8 = b'V';
    pub const SUSP: u8 = b'S';
}

/// `CA_DB` of `apps.h`: the index, its attributes, its file name, and when it was last
/// changed (`dbst`, for `ocsp`'s reloading).
pub struct CaDb {
    pub db: rustyssl_ossl::txt_db::TxtDb,
    pub unique_subject: bool,
    pub dbfname: String,
    pub modified: Option<std::time::SystemTime>,
}

/// `load_index(dbfile, db_attr)`: `unique_subject` is the caller's default (1 when it
/// passes no attributes), which the `<dbfile>.attr` file overrides.
pub fn load_index(dbfile: &str, unique_subject: bool) -> Option<CaDb> {
    let ret = (|| {
        let input = Bio::new_file(dbfile, "r")?;
        let modified = std::fs::metadata(dbfile)
            .ok()
            .and_then(|m| m.modified().ok());
        let db = rustyssl_ossl::txt_db::TxtDb::read(
            &input,
            core::ffi::c_int::try_from(field::NUMBER).unwrap_or(0),
        )?;
        let attr = format!("{dbfile}.attr");
        let mut unique = unique_subject;
        if let Some(conf) = super::apps::app_load_config_quiet(Some(&attr))
            && let Some(p) = super::apps::app_conf_try_string(&conf, None, "unique_subject")
        {
            unique = super::apps::parse_yesno(Some(&p), true);
        }
        Some(CaDb {
            db,
            unique_subject: unique,
            dbfname: dbfile.to_owned(),
            modified,
        })
    })();
    io::print_errors();
    ret
}

/// `index_index`: the serial-number index, and the name index if subjects are unique.
pub fn index_index(db: &CaDb) -> bool {
    use rustyssl_ossl::txt_db::IndexKind;
    if !db
        .db
        .create_index(field::SERIAL, IndexKind::NoLeadingZeros, false)
    {
        let (e, a1, a2) = db.db.error();
        eprintf!("Error creating serial number index:({e},{a1},{a2})\n");
        io::print_errors();
        return false;
    }
    if db.unique_subject && !db.db.create_index(field::NAME, IndexKind::Plain, true) {
        let (e, a1, a2) = db.db.error();
        eprintf!("Error creating name index:({e},{a1},{a2})\n");
        io::print_errors();
        return false;
    }
    true
}

/// `save_index(dbfile, suffix, db)`: `<dbfile>.<suffix>` and `<dbfile>.attr.<suffix>`.
pub fn save_index(dbfile: &str, suffix: &str, db: &CaDb) -> bool {
    let ok = (|| {
        if dbfile.len() + suffix.len() + 6 >= BSIZE {
            eprintf!("File name too long\n");
            return false;
        }
        let attr = format!("{dbfile}.attr");
        let attr_new = format!("{dbfile}.attr.{suffix}");
        let new = format!("{dbfile}.{suffix}");
        let Some(out) = Bio::new_file(&new, "w") else {
            perror(dbfile);
            eprintf!("Unable to open '{dbfile}'\n");
            return false;
        };
        let j = db.db.write(&out);
        drop(out);
        if j <= 0 {
            return false;
        }
        let Some(out) = Bio::new_file(&attr_new, "w") else {
            perror(&attr);
            eprintf!("Unable to open '{attr}'\n");
            return false;
        };
        let yes = if db.unique_subject { "yes" } else { "no" };
        let _ = out.write_all(format!("unique_subject = {yes}\n").as_bytes());
        true
    })();
    if !ok {
        io::print_errors();
    }
    ok
}

/// `rotate_index(dbfile, new_suffix, old_suffix)`.
pub fn rotate_index(dbfile: &str, new_suffix: &str, old_suffix: &str) -> bool {
    let ok = (|| {
        let j = (dbfile.len() + old_suffix.len()).max(dbfile.len() + new_suffix.len());
        if j + 6 >= BSIZE {
            eprintf!("File name too long\n");
            return false;
        }
        let b4 = format!("{dbfile}.attr");
        let b3 = format!("{dbfile}.attr.{old_suffix}");
        let b2 = format!("{dbfile}.attr.{new_suffix}");
        let b1 = format!("{dbfile}.{old_suffix}");
        let b0 = format!("{dbfile}.{new_suffix}");
        if let Some(e) = rename(dbfile, &b1)
            && !tolerated(&e)
        {
            eprintf!("Unable to rename {dbfile} to {b1}\n");
            reason(&e);
            return false;
        }
        if let Some(e) = rename(&b0, dbfile) {
            eprintf!("Unable to rename {b0} to {dbfile}\n");
            reason(&e);
            let _ = rename(&b1, dbfile);
            return false;
        }
        if let Some(e) = rename(&b4, &b3)
            && !tolerated(&e)
        {
            eprintf!("Unable to rename {b4} to {b3}\n");
            reason(&e);
            let _ = rename(dbfile, &b0);
            let _ = rename(&b1, dbfile);
            return false;
        }
        if let Some(e) = rename(&b2, &b4) {
            eprintf!("Unable to rename {b2} to {b4}\n");
            reason(&e);
            let _ = rename(&b3, &b4);
            let _ = rename(dbfile, &b0);
            let _ = rename(&b1, dbfile);
            return false;
        }
        true
    })();
    if !ok {
        io::print_errors();
    }
    ok
}
