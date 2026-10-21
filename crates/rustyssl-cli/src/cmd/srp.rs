//! `openssl srp` (`apps/srp.c`).
//!
//! It keeps its own copy of the index-file helpers of `apps.c` (`load_index`, `save_index`,
//! `rotate_index`; fork G3's `ca` ports them too), reduced to what a verifier file needs.

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{
    DB_SRP_INDEX, DB_SRP_MODIF, DB_SRP_REVOKED, DB_SRP_VALID, DB_srpgN, DB_srpid, DB_srpinfo,
    DB_srpsalt, DB_srptype, DB_srpverifier,
};
use rustyssl_ossl::srp::{self, FIELDS, TxtDb};

use crate::generated::options::srp::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::{app_libctx, app_rand, apps, engine, io};

const BASE_SECTION: &str = "srp";
const ENV_DATABASE: &str = "srpvfile";
const ENV_DEFAULT_SRP: &str = "default_srp";
/// `BSIZE` of `apps.c`.
const BSIZE: usize = 256;

const TYPE: usize = idx(DB_srptype);
const VERIFIER: usize = idx(DB_srpverifier);
const SALT: usize = idx(DB_srpsalt);
const ID: usize = idx(DB_srpid);
const GN: usize = idx(DB_srpgN);
const INFO: usize = idx(DB_srpinfo);

const fn idx(i: i32) -> usize {
    i.unsigned_abs() as usize
}

fn ch(c: i32) -> u8 {
    u8::try_from(c).unwrap_or(0)
}

/// `CA_DB` of `apps.h`, as the verifier file needs it.
struct CaDb {
    db: TxtDb,
    unique_subject: bool,
}

/// `BIO_printf`'s `"%s"` of a possibly-NULL string.
/// Row `i`'s fields.
fn row_fields(db: &TxtDb, i: usize) -> [Option<String>; FIELDS] {
    core::array::from_fn(|f| db.field_str(i, f))
}

fn s(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("<NULL>")
}

/// The first character of a field (`pp[f][0]`), 0 if empty.
fn first(db: &CaDb, i: usize, f: usize) -> u8 {
    db.db
        .field(i, f)
        .and_then(|v| v.first().copied())
        .unwrap_or(0)
}

fn get_index(db: &CaDb, id: Option<&str>, kind: u8) -> Option<usize> {
    let id = id?;
    let index = kind == ch(DB_SRP_INDEX);
    (0..db.db.len()).find(|&i| {
        (first(db, i, TYPE) == ch(DB_SRP_INDEX)) == index
            && db.db.field_str(i, ID).as_deref() == Some(id)
    })
}

fn print_entry(db: &CaDb, indx: Option<usize>, verbose: bool, title: &str) {
    let Some(i) = indx else { return };
    if !verbose {
        return;
    }
    let pp = row_fields(&db.db, i);
    eprintf!("{title} \"{}\"\n", s(&pp[ID]));
    for (j, f) in pp.iter().enumerate() {
        eprintf!("  {j} = \"{}\"\n", s(f));
    }
}

fn print_index(db: &CaDb, indexindex: usize, verbose: bool) {
    print_entry(db, Some(indexindex), verbose, "g N entry");
}

fn print_user(db: &CaDb, userindex: usize, verbose: bool) {
    if verbose && first(db, userindex, TYPE) != b'I' {
        print_entry(db, Some(userindex), verbose, "User entry");
        let gn = db.db.field_str(userindex, GN);
        print_entry(db, get_index(db, gn.as_deref(), b'I'), verbose, "g N entry");
    }
}

fn update_index(db: &CaDb, row: &[Option<String>; FIELDS]) -> bool {
    if !db.db.insert(&row.each_ref().map(Option::as_deref)) {
        eprintf!("failed to update srpvfile\n");
        eprintf!("TXT_DB error number {}\n", db.db.error().0);
        return false;
    }
    true
}

fn lookup_conf(conf: &rustyssl_ossl::conf::Conf, section: &str, tag: &str) -> Option<String> {
    let entry = conf.get_string(Some(section), tag);
    if entry.is_none() {
        eprintf!("variable lookup failed for {section}::{tag}\n");
    }
    entry
}

fn srp_verify_user(
    user: &str,
    srp_verifier: &Option<String>,
    srp_usersalt: &Option<String>,
    g: &Option<String>,
    n: &Option<String>,
    passin: Option<&str>,
    verbose: i32,
) -> Option<String> {
    let Ok(password) = srp::password_callback(1024, false, passin, Some(user)) else {
        return None;
    };
    if verbose > 0 {
        eprintf!(
            "Validating\n   user=\"{user}\"\n srp_verifier=\"{}\"\n srp_usersalt=\"{}\"\n g=\"{}\"\n N=\"{}\"\n",
            s(srp_verifier),
            s(srp_usersalt),
            s(g),
            s(n)
        );
    }
    if verbose > 1 {
        eprintf!("Pass {}\n", String::from_utf8_lossy(&password));
    }
    match srp::create_verifier(
        user,
        &password,
        srp_usersalt.as_deref(),
        n.as_deref(),
        g.as_deref(),
    ) {
        None => {
            eprintf!("Internal error validating SRP verifier\n");
            None
        }
        Some((gnid, _, verifier)) => {
            (srp_verifier.as_deref() == Some(verifier.as_str())).then_some(gnid)
        }
    }
}

/// `srp_create_user`: the gN id, the verifier and the salt.
fn srp_create_user(
    user: &str,
    g: &Option<String>,
    n: &Option<String>,
    passout: Option<&str>,
    verbose: i32,
) -> Option<(String, String, String)> {
    let Ok(password) = srp::password_callback(1024, true, passout, Some(user)) else {
        return None;
    };
    if verbose > 0 {
        eprintf!(
            "Creating\n user=\"{user}\"\n g=\"{}\"\n N=\"{}\"\n",
            s(g),
            s(n)
        );
    }
    let r = srp::create_verifier(user, &password, None, n.as_deref(), g.as_deref());
    if r.is_none() {
        eprintf!("Internal error creating SRP verifier\n");
    }
    if verbose > 1 {
        let (gnid, salt, ver) = match &r {
            Some((a, b, c)) => (Some(a.clone()), Some(b.clone()), Some(c.clone())),
            None => (None, None, None),
        };
        eprintf!(
            "gNid={} salt =\"{}\"\n verifier =\"{}\"\n",
            s(&gnid),
            s(&salt),
            s(&ver)
        );
    }
    r.map(|(gnid, salt, verifier)| (gnid, verifier, salt))
}

/// `load_index(dbfile, NULL)`.
fn load_index(dbfile: &str) -> Option<CaDb> {
    let result = (|| {
        let input = Bio::new_file(dbfile, "r")?;
        if std::fs::metadata(dbfile).is_err() {
            return None;
        }
        let db = TxtDb::read(&input, i32::try_from(FIELDS).unwrap_or(6))?;
        let mut unique_subject = true;
        let attr = format!("{dbfile}.attr");
        if let Some(conf) = apps::app_load_config_quiet(Some(&attr))
            && let Some(p) = apps::app_conf_try_string(&conf, None, "unique_subject")
        {
            unique_subject = apps::parse_yesno(Some(&p), true);
        }
        Some(CaDb { db, unique_subject })
    })();
    io::print_errors();
    result
}

/// `save_index(dbfile, suffix, db)`.
fn save_index(dbfile: &str, suffix: &str, db: &CaDb) -> bool {
    let ok = (|| {
        if dbfile.len() + suffix.len() + 6 >= BSIZE {
            eprintf!("File name too long\n");
            return false;
        }
        let attr = format!("{dbfile}.attr");
        let attr_new = format!("{dbfile}.attr.{suffix}");
        let new = format!("{dbfile}.{suffix}");
        let Some(out) = Bio::new_file(&new, "w") else {
            srp::perror(dbfile);
            eprintf!("Unable to open '{dbfile}'\n");
            return false;
        };
        let j = db.db.write(&out);
        drop(out);
        if j <= 0 {
            return false;
        }
        let Some(out) = Bio::new_file(&attr_new, "w") else {
            srp::perror(&attr);
            eprintf!("Unable to open '{attr}'\n");
            return false;
        };
        let us = if db.unique_subject { "yes" } else { "no" };
        let _ = out.write_all(format!("unique_subject = {us}\n").as_bytes());
        true
    })();
    if !ok {
        io::print_errors();
    }
    ok
}

/// `rename`, with `errno` set on failure (for `perror`).
fn rename(from: &str, to: &str) -> Result<(), std::io::ErrorKind> {
    std::fs::rename(from, to).map_err(|e| e.kind())
}

/// `rotate_index(dbfile, new_suffix, old_suffix)`.
fn rotate_index(dbfile: &str, new_suffix: &str, old_suffix: &str) -> bool {
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
        // ENOENT and ENOTDIR.
        let missing = |e: std::io::ErrorKind| {
            matches!(
                e,
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            )
        };
        if let Err(e) = rename(dbfile, &b1)
            && !missing(e)
        {
            eprintf!("Unable to rename {dbfile} to {b1}\n");
            srp::perror("reason");
            return false;
        }
        if rename(&b0, dbfile).is_err() {
            eprintf!("Unable to rename {b0} to {dbfile}\n");
            srp::perror("reason");
            let _ = rename(&b1, dbfile);
            return false;
        }
        if let Err(e) = rename(&b4, &b3)
            && !missing(e)
        {
            eprintf!("Unable to rename {b4} to {b3}\n");
            srp::perror("reason");
            let _ = rename(dbfile, &b0);
            let _ = rename(&b1, dbfile);
            return false;
        }
        if rename(&b2, &b4).is_err() {
            eprintf!("Unable to rename {b2} to {b4}\n");
            srp::perror("reason");
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    None,
    Add,
    Delete,
    Modify,
    List,
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let mut errors = 0;
    let mut verbose = 0;
    let mut mode = Mode::None;
    let (mut passinarg, mut passoutarg): (Option<String>, Option<String>) = (None, None);
    let (mut gn, mut userinfo, mut section): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut configfile, mut srpvfile): (Option<String>, Option<String>) = (None, None);
    let mut _engine = None;
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
    };
    loop {
        let o = p.next();
        match o {
            Opt::EOF => break,
            Opt::ERR => {
                opthelp(&prog);
                return finish(1, errors, verbose);
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return finish(0, errors, verbose);
            }
            Opt::VERBOSE => verbose += 1,
            Opt::CONFIG => configfile = Some(p.arg().to_owned()),
            Opt::NAME => section = Some(p.arg().to_owned()),
            Opt::SRPVFILE => srpvfile = Some(p.arg().to_owned()),
            Opt::ADD | Opt::DELETE | Opt::MODIFY | Opt::LIST => {
                if mode != Mode::None {
                    eprintf!("{prog}: Only one of -add/-delete/-modify/-list\n");
                    opthelp(&prog);
                    return finish(1, errors, verbose);
                }
                mode = match o {
                    Opt::ADD => Mode::Add,
                    Opt::DELETE => Mode::Delete,
                    Opt::MODIFY => Mode::Modify,
                    _ => Mode::List,
                };
            }
            Opt::GN => gn = Some(p.arg().to_owned()),
            Opt::USERINFO => userinfo = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => _engine = engine::setup_engine(Some(p.arg()), false),
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, p.arg()) {
                    return finish(1, errors, verbose);
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return finish(1, errors, verbose);
                }
            }
        }
    }
    // Optional parameters are usernames.
    let users: Vec<String> = p.rest().to_vec();
    let mut args = users.iter();
    if !app_rand::load() {
        return finish(1, errors, verbose);
    }
    if srpvfile.is_some() && configfile.is_some() {
        eprintf!("-srpvfile and -configfile cannot be specified together.\n");
        return finish(1, errors, verbose);
    }
    if mode == Mode::None {
        eprintf!("Exactly one of the options -add, -delete, -modify -list must be specified.\n");
        opthelp(&prog);
        return finish(1, errors, verbose);
    }
    let mut user: Option<String> = None;
    if matches!(mode, Mode::Delete | Mode::Modify | Mode::Add) {
        if users.is_empty() {
            eprintf!("Need at least one user.\n");
            opthelp(&prog);
            return finish(1, errors, verbose);
        }
        user = args.next().cloned();
    }
    if (passinarg.is_some() || passoutarg.is_some()) && users.len() != 1 {
        eprintf!("-passin, -passout arguments only valid with one user.\n");
        opthelp(&prog);
        return finish(1, errors, verbose);
    }
    let Some((passin, passout)) = apps::app_passwd(passinarg.as_deref(), passoutarg.as_deref())
    else {
        eprintf!("Error getting passwords\n");
        return finish(1, errors, verbose);
    };
    let passin = passin.as_ref().map(|p| p.as_str().to_owned());
    let passout = passout.as_ref().map(|p| p.as_str().to_owned());

    let mut _conf = None;
    let srpvfile = match srpvfile {
        Some(f) => f,
        None => {
            let given = configfile.is_some();
            let file = configfile
                .or_else(apps::default_config_file)
                .unwrap_or_default();
            let Some(conf) = apps::app_load_config_verbose(&file, verbose > 0) else {
                return finish(1, errors, verbose);
            };
            if given && !apps::app_load_modules(Some(&conf)) {
                return finish(1, errors, verbose);
            }
            // Lets get the config section we are using.
            let section = match section {
                Some(s) => s,
                None => {
                    if verbose > 0 {
                        eprintf!("trying to read {ENV_DEFAULT_SRP} in {BASE_SECTION}\n");
                    }
                    match lookup_conf(&conf, BASE_SECTION, ENV_DEFAULT_SRP) {
                        Some(s) => s,
                        None => return finish(1, errors, verbose),
                    }
                }
            };
            app_rand::load_conf(&conf, Some(BASE_SECTION));
            if verbose > 0 {
                eprintf!("trying to read {ENV_DATABASE} in section \"{section}\"\n");
            }
            let Some(f) = lookup_conf(&conf, &section, ENV_DATABASE) else {
                return finish(1, errors, verbose);
            };
            _conf = Some(conf);
            f
        }
    };
    if verbose > 0 {
        eprintf!("Trying to read SRP verifier file \"{srpvfile}\"\n");
    }
    let Some(db) = load_index(&srpvfile) else {
        eprintf!("Problem with index file: {srpvfile} (could not load/parse file)\n");
        return finish(1, errors, verbose);
    };

    // Lets check some fields.
    let mut gnindex = None;
    let mut maxgn: Option<usize> = None;
    for i in 0..db.db.len() {
        if first(&db, i, TYPE) == ch(DB_SRP_INDEX) {
            maxgn = Some(i);
            if gnindex.is_none() && gn.is_some() && db.db.field_str(i, ID) == gn {
                gnindex = Some(i);
            }
            print_index(&db, i, verbose > 1);
        }
    }
    if verbose > 0 {
        eprintf!("Database initialised\n");
    }
    let gnrow: Option<[Option<String>; FIELDS]> = if let Some(g) = gnindex {
        print_entry(&db, Some(g), verbose > 1, "Default g and N");
        Some(row_fields(&db.db, g))
    } else if maxgn.is_some_and(|m| m > 0) && !srp::default_gn_exists(gn.as_deref()) {
        eprintf!("No g and N value for index \"{}\"\n", s(&gn));
        return finish(1, errors, verbose);
    } else {
        if verbose > 0 {
            eprintf!("Database has no g N information.\n");
        }
        None
    };
    let gnrow_salt = gnrow.as_ref().and_then(|r| r[SALT].clone());
    let gnrow_verifier = gnrow.as_ref().and_then(|r| r[VERIFIER].clone());

    if verbose > 1 {
        eprintf!("Starting user processing\n");
    }
    let mut doupdatedb = false;
    let mut abandoned = false;
    while mode == Mode::List || user.is_some() {
        if let Some(u) = &user
            && verbose > 1
        {
            eprintf!("Processing user \"{u}\"\n");
        }
        let userindex = get_index(&db, user.as_deref(), b'U');
        if let Some(ui) = userindex {
            print_user(&db, ui, verbose > 0 || mode == Mode::List);
        }
        match mode {
            Mode::List => match (&user, userindex) {
                (None, _) => {
                    eprintf!("List all users\n");
                    for i in 0..db.db.len() {
                        print_user(&db, i, true);
                    }
                }
                (Some(u), None) => {
                    eprintf!("user \"{u}\" does not exist, ignored. t\n");
                    errors += 1;
                }
                _ => {}
            },
            Mode::Add => {
                let u = user.clone().unwrap_or_default();
                if let Some(ui) = userindex {
                    // Reactivation of a new user.
                    eprintf!("user \"{u}\" reactivated.\n");
                    db.db.set_first_char(ui, TYPE, b'V');
                    doupdatedb = true;
                } else {
                    let g = if gnrow.is_some() {
                        gnrow_salt.clone()
                    } else {
                        gn.clone()
                    };
                    let Some((gnid, verifier, salt)) =
                        srp_create_user(&u, &g, &gnrow_verifier, passout.as_deref(), verbose)
                    else {
                        eprintf!(
                            "Cannot create srp verifier for user \"{u}\", operation abandoned .\n"
                        );
                        errors += 1;
                        abandoned = true;
                        break;
                    };
                    let row = [
                        Some("v".to_owned()),
                        Some(verifier),
                        Some(salt),
                        Some(u.clone()),
                        Some(gnid),
                        userinfo.clone(),
                    ];
                    if !update_index(&db, &row) {
                        abandoned = true;
                        break;
                    }
                    doupdatedb = true;
                }
            }
            Mode::Modify => {
                let u = user.clone().unwrap_or_default();
                match userindex {
                    None => {
                        eprintf!("user \"{u}\" does not exist, operation ignored.\n");
                        errors += 1;
                    }
                    Some(ui) => {
                        let row = row_fields(&db.db, ui);
                        let kind = first(&db, ui, TYPE);
                        if kind == ch(DB_SRP_MODIF) {
                            eprintf!("user \"{u}\" already updated, operation ignored.\n");
                            errors += 1;
                        } else {
                            if kind == ch(DB_SRP_VALID) {
                                if verbose > 0 {
                                    eprintf!("Verifying password for user \"{u}\"\n");
                                }
                                // As upstream: the user's own row, not its gN index's.
                                let irow = get_index(&db, row[GN].as_deref(), ch(DB_SRP_INDEX))
                                    .map(|_| row.clone());
                                let (g, n) = match &irow {
                                    Some(r) => (r[SALT].clone(), r[VERIFIER].clone()),
                                    None => (row[GN].clone(), None),
                                };
                                if srp_verify_user(
                                    &u,
                                    &row[VERIFIER],
                                    &row[SALT],
                                    &g,
                                    &n,
                                    passin.as_deref(),
                                    verbose,
                                )
                                .is_none()
                                {
                                    eprintf!(
                                        "Invalid password for user \"{u}\", operation abandoned.\n"
                                    );
                                    errors += 1;
                                    abandoned = true;
                                    break;
                                }
                            }
                            if verbose > 0 {
                                eprintf!("Password for user \"{u}\" ok.\n");
                            }
                            let Some((gnid, verifier, salt)) = srp_create_user(
                                &u,
                                &gnrow_salt,
                                &gnrow_verifier,
                                passout.as_deref(),
                                verbose,
                            ) else {
                                eprintf!(
                                    "Cannot create srp verifier for user \"{u}\", operation abandoned.\n"
                                );
                                errors += 1;
                                abandoned = true;
                                break;
                            };
                            db.db.set_field(ui, VERIFIER, Some(&verifier));
                            db.db.set_field(ui, SALT, Some(&salt));
                            db.db.set_first_char(ui, TYPE, b'v');
                            db.db.set_field(ui, GN, Some(&gnid));
                            if let Some(info) = &userinfo {
                                db.db.set_field(ui, INFO, Some(info));
                            }
                            doupdatedb = true;
                        }
                    }
                }
            }
            Mode::Delete => {
                let u = user.clone().unwrap_or_default();
                match userindex {
                    None => {
                        eprintf!("user \"{u}\" does not exist, operation ignored. t\n");
                        errors += 1;
                    }
                    Some(ui) => {
                        eprintf!("user \"{u}\" revoked. t\n");
                        db.db.set_first_char(ui, TYPE, ch(DB_SRP_REVOKED));
                        doupdatedb = true;
                    }
                }
            }
            Mode::None => {}
        }
        user = args.next().cloned();
        if user.is_none() {
            // No more processing in any mode if no users left.
            break;
        }
    }
    if abandoned {
        return finish(1, errors, verbose);
    }
    if verbose > 0 {
        eprintf!("User procession done.\n");
    }
    if doupdatedb {
        // Lets check some fields.
        for i in 0..db.db.len() {
            if first(&db, i, TYPE) == ch(DB_SRP_MODIF) {
                db.db.set_first_char(i, TYPE, b'V');
                print_user(&db, i, verbose > 0);
            }
        }
        if verbose > 0 {
            eprintf!("Trying to update srpvfile.\n");
        }
        if !save_index(&srpvfile, "new", &db) {
            return finish(1, errors, verbose);
        }
        if verbose > 0 {
            eprintf!("Temporary srpvfile created.\n");
        }
        if !rotate_index(&srpvfile, "new", "old") {
            return finish(1, errors, verbose);
        }
        if verbose > 0 {
            eprintf!("srpvfile updated.\n");
        }
    }
    finish(i32::from(errors != 0), errors, verbose)
}

/// The `end:` label: the error count, the exit code, and the error queue on failure.
fn finish(ret: i32, errors: i32, verbose: i32) -> i32 {
    if errors != 0 && verbose > 0 {
        eprintf!("User errors {errors}.\n");
    }
    if verbose > 0 {
        eprintf!("SRP terminating with code {ret}.\n");
    }
    if ret != 0 {
        io::print_errors();
    }
    ret
}
