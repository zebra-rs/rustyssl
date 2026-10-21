//! `openssl list` (`apps/list.c`), with `print_names` and its helpers of `apps/lib/names.c`.

use std::io::Write;

use rustyssl_ossl::abi::{
    ASN1_PKEY_ALIAS, ASN1_PKEY_DYNAMIC, EVP_RAND_STATE_ERROR, EVP_RAND_STATE_READY,
    EVP_RAND_STATE_UNINITIALISED, OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING, OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_NAME,
    OSSL_PROV_PARAM_STATUS, OSSL_PROV_PARAM_VERSION, OSSL_RAND_PARAM_STATE, TLS1_2_VERSION,
    TLS1_3_VERSION,
};
use rustyssl_ossl::algorithm::{
    self as alg, Algorithm, AsymCipherAlg, CipherAlg, DecoderAlg, EncoderAlg, GroupsError,
    Instance, KdfAlg, KemAlg, KeyexchAlg, KeymgmtAlg, Legacy, MacAlg, MdAlg, Object, Order,
    RandAlg, RandInstance, SignatureAlg, SkeymgmtAlg, StoreLoaderAlg,
};
use rustyssl_ossl::evp::{Cipher, Md};
use rustyssl_ossl::params::Query;
use rustyssl_ossl::{err, provider};

use crate::generated::options::list::{OPTIONS, Opt};
use crate::generated::options::{DISABLED, FUNCTIONS, FuncType, option_entries};
use crate::lib::app_params::print_param_types;
use crate::lib::opt::{self, Marker, Parser, eprintf};
use crate::lib::{app_libctx, io};

/// Writes to standard output (`BIO_printf(bio_out, ...)`).
macro_rules! out {
    ($($arg:tt)*) => {{
        let _ = write!(io::out(), $($arg)*);
    }};
}

/// The listing's settings (`verbose` and `select_name` of `list.c`).
struct List {
    verbose: bool,
    select: Option<String>,
}

fn libctx() -> Option<std::rc::Rc<rustyssl_ossl::provider::LibCtx>> {
    app_libctx::libctx()
}

/// `include_legacy`: the legacy tables are listed only without a property query.
fn include_legacy() -> bool {
    app_libctx::propq().is_none()
}

/// `print_names`: the names sorted (`name_cmp`), braced when there are several.
fn names_text(names: Vec<String>) -> String {
    let names = alg::sk_sorted(names, Order::Casecmp, |n| (n.clone(), String::new()));
    let mut s = String::new();
    if names.len() > 1 {
        s.push_str("{ ");
    }
    s.push_str(&names.join(", "));
    if names.len() > 1 {
        s.push_str(" }");
    }
    s
}

/// The algorithms of one kind every provider offers that can be fetched by name (`collect_*`
/// with `is_*_fetchable`), sorted by provider (`*_cmp`).
fn collected<A: Algorithm>(check_fetch: bool) -> Vec<A> {
    let lc = libctx();
    let propq = app_libctx::propq();
    let found: Vec<A> = A::provided(lc.as_deref())
        .into_iter()
        .filter(|a| !check_fetch || a.fetchable(lc.as_deref(), propq.as_deref()))
        .collect();
    alg::sk_sorted(found, Order::Strcmp, |a| (a.provider_name(), String::new()))
}

impl List {
    fn skip<A: Algorithm>(&self, a: &A) -> bool {
        self.select.as_deref().is_some_and(|s| !a.is_a(s))
    }

    fn description(&self, desc: Option<String>) {
        if let Some(d) = desc {
            out!("    description: {d}\n");
        }
    }

    /// `list_ciphers`.
    fn ciphers(&self, prefix: &str) {
        if include_legacy() {
            out!("{prefix}Legacy:\n");
            for entry in alg::legacy_ciphers() {
                match entry {
                    Legacy::Algorithm(name) => {
                        if self
                            .select
                            .as_deref()
                            .is_some_and(|s| !s.eq_ignore_ascii_case(&name))
                        {
                            continue;
                        }
                        out!("  {name}\n");
                    }
                    Legacy::Alias(from, to) => {
                        if self.select.is_some() {
                            continue;
                        }
                        out!(
                            "  {} => {}\n",
                            from.as_deref().unwrap_or("<undefined>"),
                            to.as_deref().unwrap_or("<undefined>")
                        );
                    }
                }
            }
        }
        out!("{prefix}Provided:\n");
        for c in collected::<CipherAlg>(true) {
            if self.skip(&c) {
                continue;
            }
            let Some(names) = c.names() else {
                continue;
            };
            out!("  {} @ {}\n", names_text(names), c.provider_name());
            if self.verbose {
                self.description(c.description());
                print_param_types("retrievable algorithm parameters", c.gettable_params(), 4);
                print_param_types(
                    "retrievable operation parameters",
                    c.gettable_ctx_params(),
                    4,
                );
                print_param_types("settable operation parameters", c.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_digests`.
    fn digests(&self, prefix: &str) {
        if include_legacy() {
            out!("{prefix}Legacy:\n");
            for entry in alg::legacy_digests() {
                match entry {
                    Legacy::Algorithm(name) => out!("  {name}\n"),
                    Legacy::Alias(from, to) => out!(
                        "  {} => {}\n",
                        from.as_deref().unwrap_or("<undefined>"),
                        to.as_deref().unwrap_or("<undefined>")
                    ),
                }
            }
        }
        out!("{prefix}Provided:\n");
        for m in collected::<MdAlg>(true) {
            if self.skip(&m) {
                continue;
            }
            let Some(names) = m.names() else {
                continue;
            };
            out!("  {} @ {}\n", names_text(names), m.provider_name());
            if self.verbose {
                self.description(m.description());
                print_param_types("retrievable algorithm parameters", m.gettable_params(), 4);
                print_param_types(
                    "retrievable operation parameters",
                    m.gettable_ctx_params(),
                    4,
                );
                print_param_types("settable operation parameters", m.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_macs`.
    fn macs(&self) {
        out!("Provided MACs:\n");
        for m in collected::<MacAlg>(true) {
            if self.skip(&m) {
                continue;
            }
            let Some(names) = m.names() else {
                continue;
            };
            out!("  {} @ {}\n", names_text(names), m.provider_name());
            if self.verbose {
                self.description(m.description());
                print_param_types("retrievable algorithm parameters", m.gettable_params(), 4);
                print_param_types(
                    "retrievable operation parameters",
                    m.gettable_ctx_params(),
                    4,
                );
                print_param_types("settable operation parameters", m.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_kdfs`.
    fn kdfs(&self) {
        out!("Provided KDFs and PDFs:\n");
        for k in collected::<KdfAlg>(true) {
            if self.skip(&k) {
                continue;
            }
            let Some(names) = k.names() else {
                continue;
            };
            out!("  {} @ {}\n", names_text(names), k.provider_name());
            if self.verbose {
                self.description(k.description());
                print_param_types("retrievable algorithm parameters", k.gettable_params(), 4);
                print_param_types(
                    "retrievable operation parameters",
                    k.gettable_ctx_params(),
                    4,
                );
                print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_random_generators`.
    fn random_generators(&self) {
        out!("Provided RNGs and seed sources:\n");
        let lc = libctx();
        let propq = app_libctx::propq();
        let found: Vec<RandAlg> = RandAlg::provided(lc.as_deref())
            .into_iter()
            .filter(|r| r.fetchable(lc.as_deref(), propq.as_deref()))
            .collect();
        let rands = alg::sk_sorted(found, Order::CasecmpThenStrcmp, |r| {
            (r.name().unwrap_or_default(), r.provider_name())
        });
        for r in rands {
            let name = r.name().unwrap_or_default();
            if self
                .select
                .as_deref()
                .is_some_and(|s| !name.eq_ignore_ascii_case(s))
            {
                continue;
            }
            out!("  {name} @ {}\n", r.provider_name());
            if self.verbose {
                self.description(r.description());
                print_param_types("retrievable algorithm parameters", r.gettable_params(), 4);
                print_param_types(
                    "retrievable operation parameters",
                    r.gettable_ctx_params(),
                    4,
                );
                print_param_types("settable operation parameters", r.settable_ctx_params(), 4);
            }
        }
    }

    /// `display_random`.
    fn display_random(&self, name: &str, which: Instance) {
        out!("{name}:\n");
        let Some(drbg) = RandInstance::get(which) else {
            return;
        };
        out!("  {} @ {}\n", drbg.name(), drbg.provider_name());
        let state = match drbg.state() {
            EVP_RAND_STATE_UNINITIALISED => "uninitialised",
            EVP_RAND_STATE_READY => "ready",
            EVP_RAND_STATE_ERROR => "error",
            _ => "unknown",
        };
        out!("  state = {state}\n");
        let is = |t: u32, c: i32| u32::try_from(c).is_ok_and(|c| c == t);
        for g in drbg.gettable_ctx_params().iter() {
            let key = g.key();
            // The state is shown already.
            if key.eq_ignore_ascii_case(OSSL_RAND_PARAM_STATE.to_str().unwrap_or_default()) {
                continue;
            }
            let t = g.data_type();
            // Only strings, unless verbose.
            if !is(t, OSSL_PARAM_UTF8_STRING) && !is(t, OSSL_PARAM_UTF8_PTR) && !self.verbose {
                continue;
            }
            let size = if is(t, OSSL_PARAM_UNSIGNED_INTEGER) || is(t, OSSL_PARAM_INTEGER) {
                8
            } else {
                1000
            };
            let mut q = Query::new().buffer(&key, t, size);
            if drbg.get_params(&mut q)
                && let Some(p) = q.get(0)
            {
                crate::lib::app_params::print_param_value(&p, 2);
            }
        }
    }

    /// `list_encoders`.
    fn encoders(&self) {
        out!("Provided ENCODERs:\n");
        for k in collected::<EncoderAlg>(true) {
            if self.skip(&k) {
                continue;
            }
            let Some(names) = k.names() else {
                continue;
            };
            out!(
                "  {} @ {} ({})\n",
                names_text(names),
                k.provider_name(),
                k.properties().as_deref().unwrap_or("<NULL>")
            );
            if self.verbose {
                self.description(k.description());
                print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_decoders`.
    fn decoders(&self) {
        out!("Provided DECODERs:\n");
        for k in collected::<DecoderAlg>(true) {
            if self.skip(&k) {
                continue;
            }
            let Some(names) = k.names() else {
                continue;
            };
            out!(
                "  {} @ {} ({})\n",
                names_text(names),
                k.provider_name(),
                k.properties().as_deref().unwrap_or("<NULL>")
            );
            if self.verbose {
                self.description(k.description());
                print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            }
        }
    }

    /// The `Name:` block of a key manager.
    fn key_manager_block<A: Algorithm>(&self, k: &A) -> bool {
        let Some(names) = k.names() else {
            return false;
        };
        let first = names
            .first()
            .cloned()
            .unwrap_or_else(|| "<NULL>".to_owned());
        let name = k.description().unwrap_or(first);
        out!(
            "  Name: {name}\n    Type: Provider Algorithm\n    IDs: {} @ {}\n",
            names_text(names),
            k.provider_name()
        );
        true
    }

    /// `list_keymanagers`.
    fn keymanagers(&self) {
        for k in collected::<KeymgmtAlg>(true) {
            if self.skip(&k) {
                continue;
            }
            if self.key_manager_block(&k) && self.verbose {
                print_param_types(
                    "settable key generation parameters",
                    k.gen_settable_params(),
                    4,
                );
                print_param_types("settable operation parameters", k.settable_params(), 4);
                print_param_types("retrievable operation parameters", k.gettable_params(), 4);
            }
        }
    }

    /// `list_skeymanagers`.
    fn skeymanagers(&self) {
        for k in collected::<SkeymgmtAlg>(true) {
            if self.skip(&k) {
                continue;
            }
            self.key_manager_block(&k);
        }
    }

    /// The common shape of `list_signatures`, `list_kems`, `list_asymciphers` and
    /// `list_keyexchanges`: ` -` when none is listed.
    fn operations<A: Algorithm>(&self, tables: impl Fn(&A)) {
        let mut count = 0;
        for k in collected::<A>(true) {
            if self.skip(&k) {
                continue;
            }
            let Some(names) = k.names() else {
                continue;
            };
            count += 1;
            out!("  {} @ {}\n", names_text(names), k.provider_name());
            if self.verbose {
                self.description(k.description());
                tables(&k);
            }
        }
        if count == 0 {
            out!(" -\n");
        }
    }

    fn signatures(&self) {
        self.operations::<SignatureAlg>(|k| {
            print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            print_param_types(
                "retrievable operation parameters",
                k.gettable_ctx_params(),
                4,
            );
        });
    }

    fn kems(&self) {
        self.operations::<KemAlg>(|k| {
            print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            print_param_types(
                "retrievable operation parameters",
                k.gettable_ctx_params(),
                4,
            );
        });
    }

    fn asymciphers(&self) {
        self.operations::<AsymCipherAlg>(|k| {
            print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            print_param_types(
                "retrievable operation parameters",
                k.gettable_ctx_params(),
                4,
            );
        });
    }

    fn keyexchanges(&self) {
        self.operations::<KeyexchAlg>(|k| {
            print_param_types("settable operation parameters", k.settable_ctx_params(), 4);
            print_param_types(
                "retrievable operation parameters",
                k.gettable_ctx_params(),
                4,
            );
        });
    }

    /// `list_store_loaders`.
    fn store_loaders(&self) {
        out!("Provided STORE LOADERs:\n");
        for l in collected::<StoreLoaderAlg>(false) {
            if self.skip(&l) {
                continue;
            }
            let Some(names) = l.names() else {
                continue;
            };
            out!("  {} @ {}\n", names_text(names), l.provider_name());
            if self.verbose {
                self.description(l.description());
                print_param_types("settable operation parameters", l.settable_ctx_params(), 4);
            }
        }
    }

    /// `list_pkey`.
    fn pkey(&self) {
        if self.select.is_none() && include_legacy() {
            out!("Legacy:\n");
            let ln = |nid| alg::nid2ln(nid).unwrap_or_else(|| "<NULL>".to_owned());
            for m in alg::asn1_methods() {
                if m.flags & ASN1_PKEY_ALIAS != 0 {
                    out!(" Name: {}\n\tAlias for: {}\n", ln(m.id), ln(m.base_id));
                } else {
                    out!(
                        " Name: {}\n\tType: {} Algorithm\n\tOID: {}\n\tPEM string: {}\n",
                        m.info.as_deref().unwrap_or("<NULL>"),
                        if m.flags & ASN1_PKEY_DYNAMIC != 0 {
                            "External"
                        } else {
                            "Builtin"
                        },
                        ln(m.id),
                        m.pem_str.as_deref().unwrap_or("(none)")
                    );
                }
            }
        }
        out!("Provided:\n Key Managers:\n");
        self.keymanagers();
    }

    /// `list_pkey_meth`.
    fn pkey_meth(&self) {
        if self.select.is_none() && include_legacy() {
            out!("Legacy:\n");
            for (id, flags) in alg::pkey_methods() {
                out!(
                    " {}\n\tType: {} Algorithm\n",
                    alg::nid2ln(id).as_deref().unwrap_or("<NULL>"),
                    if flags & ASN1_PKEY_DYNAMIC != 0 {
                        "External"
                    } else {
                        "Builtin"
                    }
                );
            }
        }
        out!("Provided:\n Encryption:\n");
        self.asymciphers();
        out!(" Key Exchange:\n");
        self.keyexchanges();
        out!(" Signatures:\n");
        self.signatures();
        out!(" Key encapsulation:\n");
        self.kems();
    }

    /// `list_provider_info`.
    fn provider_info(&self) {
        let Some(providers) = provider::all() else {
            eprintf!("ERROR: Memory allocation\n");
            return;
        };
        out!("Providers:\n");
        let providers = alg::sk_sorted(providers, Order::Strcmp, |p| (p.name(), String::new()));
        for prov in providers {
            let provname = prov.name();
            out!("  {provname}\n");
            // The known information parameters, in the order printed.
            let s = |c: &std::ffi::CStr| c.to_str().unwrap_or_default().to_owned();
            let mut q = Query::new()
                .utf8_ptr(&s(OSSL_PROV_PARAM_NAME))
                .utf8_ptr(&s(OSSL_PROV_PARAM_VERSION))
                .int(&s(OSSL_PROV_PARAM_STATUS))
                .utf8_ptr(&s(OSSL_PROV_PARAM_BUILDINFO));
            q.set_all_unmodified();
            if !prov.get_params(&mut q) {
                eprintf!("WARNING: Unable to query provider parameters for {provname}\n");
                continue;
            }
            let text = |i| q.ptr_string(i).unwrap_or_else(|| "<NULL>".to_owned());
            if q.modified(0) {
                out!("    name: {}\n", text(0));
            }
            if q.modified(1) {
                out!("    version: {}\n", text(1));
            }
            if q.modified(2) {
                let active = q.int_value(2).unwrap_or(0) != 0;
                out!("    status: {}active\n", if active { "" } else { "in" });
            }
            if self.verbose {
                if q.modified(3) {
                    out!("    build info: {}\n", text(3));
                }
                print_param_types("gettable provider parameters", prov.gettable_params(), 4);
            }
        }
    }
}

/// `list_tls_groups`.
fn tls_groups(version: i32, all: bool) {
    match alg::tls_groups(version, all) {
        Ok(groups) => {
            let n = groups.len();
            for (i, g) in groups.iter().enumerate() {
                out!("{g}{}", if i + 1 < n { ':' } else { '\n' });
            }
        }
        Err(GroupsError::Memory) => {
            eprintf!("ERROR: Memory allocation\n");
        }
        Err(GroupsError::Version) => {
            eprintf!("ERROR: setting TLS protocol version\n");
        }
        Err(GroupsError::List) => {
            eprintf!("ERROR: getting implemented TLS group list\n");
        }
    }
}

/// `list_tls_signatures`.
fn tls_signatures() {
    let mut listed = 0;
    let lc = libctx();
    if let Some(builtin) = alg::builtin_sigalgs(lc.as_deref())
        && !builtin.is_empty()
    {
        out!("{builtin}");
        listed = 1;
    }
    let (ok, names) = alg::provider_tls_sigalgs();
    for name in names {
        if listed > 0 {
            out!(":");
        }
        out!("{name}");
        // A sigalg a provider registers.
        listed = 2;
    }
    if !ok {
        eprintf!("ERROR: could not list all provider signature algorithms\n");
    }
    if listed < 2 {
        out!("\nNo TLS sig algs registered by currently active providers");
    }
    out!("\n");
}

/// `list_objects`.
fn objects() {
    let max = alg::max_nid();
    let mut oid_size = 0;
    // NID 0 is NID_undef.
    for nid in 1..max {
        match alg::object(nid, &mut oid_size) {
            Object::Undefined => {}
            Object::NoOid(sn, ln) => out!(
                "# None-OID object: {}, {}\n",
                sn.as_deref().unwrap_or("<NULL>"),
                ln.as_deref().unwrap_or("<NULL>")
            ),
            Object::Error => break,
            Object::Oid(sn, ln, oid) => {
                let sn = sn.unwrap_or_else(|| "<NULL>".to_owned());
                match ln {
                    Some(ln) if ln != sn => out!("{sn} = {ln}, {oid}\n"),
                    _ => out!("{sn} = {oid}\n"),
                }
            }
        }
    }
}

/// `list_options_for_command`: each option's name and value type (`list -options`).
fn options_for_command(command: &str) {
    let Some(f) = FUNCTIONS.iter().find(|f| f.name == command) else {
        eprintf!("Invalid command '{command}'; type \"help\" for a list.\n");
        return;
    };
    let Some(entries) = f.options.and_then(option_entries) else {
        return;
    };
    for (name, marker, valtype) in entries {
        match marker {
            Some(Marker::Param) => break,
            Some(_) => continue,
            None if name.is_empty() => continue,
            None => {}
        }
        let c = if valtype == 0 {
            '-'
        } else {
            char::from(valtype)
        };
        out!("{name} {c}\n");
    }
    // The -- marker, which is sometimes documented.
    out!("- -\n");
}

/// `is_md_available`.
fn md_available(name: &str) -> bool {
    let lc = libctx();
    let propq = app_libctx::propq();
    err::set_mark();
    let md = Md::fetch(lc.as_deref(), name, propq.as_deref());
    err::pop_to_mark();
    md.is_some() || (propq.is_none() && alg::digest_from_engine(name))
}

/// `is_cipher_available`.
fn cipher_available(name: &str) -> bool {
    let lc = libctx();
    let propq = app_libctx::propq();
    err::set_mark();
    let c = Cipher::fetch(lc.as_deref(), name, propq.as_deref());
    err::pop_to_mark();
    c.is_some() || (propq.is_none() && alg::cipher_from_engine(name))
}

/// `list_type`: the commands of one type, in columns (or one a line).
fn list_type(ft: FuncType, one: bool) {
    let (columns, width) = crate::calculate_columns();
    let mut text = String::new();
    let mut i = 0;
    for f in crate::sorted_functions() {
        if f.kind != ft {
            continue;
        }
        let available = match ft {
            FuncType::Cipher => cipher_available(f.name),
            FuncType::Md => md_available(f.name),
            _ => true,
        };
        if !available {
            continue;
        }
        if one {
            text.push_str(&format!("{}\n", f.name));
        } else {
            if i % columns == 0 && i > 0 {
                text.push('\n');
            }
            text.push_str(&format!("{:<width$}", f.name));
            i += 1;
        }
    }
    if !one {
        text.push_str("\n\n");
    }
    out!("{text}");
}

/// `list_disabled`.
fn disabled() {
    out!("Disabled algorithms:\n");
    for d in DISABLED {
        out!("{d}");
    }
}

/// What to list, in the order upstream prints it.
#[derive(Default)]
struct Todo {
    commands: bool,
    all_algorithms: bool,
    random_instances: bool,
    random_generators: bool,
    digest_commands: bool,
    digest_algorithms: bool,
    kdf_algorithms: bool,
    mac_algorithms: bool,
    cipher_commands: bool,
    cipher_algorithms: bool,
    encoder_algorithms: bool,
    decoder_algorithms: bool,
    keymanager_algorithms: bool,
    skeymanager_algorithms: bool,
    signature_algorithms: bool,
    tls_signature_algorithms: bool,
    keyexchange_algorithms: bool,
    kem_algorithms: bool,
    tls_groups: bool,
    asym_cipher_algorithms: bool,
    pk_algorithms: bool,
    pk_method: bool,
    store_loaders: bool,
    provider_info: bool,
    engines: bool,
    disabled: bool,
    objects: bool,
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut l = List {
        verbose: false,
        select: None,
    };
    let (mut one, mut done) = (false, false);
    let mut all_tls_groups = false;
    let mut tls_version = TLS1_3_VERSION;
    let mut todo = Todo::default();
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::ONE => one = true,
            Opt::ALL_ARGORITHMS => todo.all_algorithms = true,
            Opt::COMMANDS => todo.commands = true,
            Opt::DIGEST_COMMANDS => todo.digest_commands = true,
            Opt::DIGEST_ALGORITHMS => todo.digest_algorithms = true,
            Opt::KDF_ALGORITHMS => todo.kdf_algorithms = true,
            Opt::RANDOM_INSTANCES => todo.random_instances = true,
            Opt::RANDOM_GENERATORS => todo.random_generators = true,
            Opt::MAC_ALGORITHMS => todo.mac_algorithms = true,
            Opt::CIPHER_COMMANDS => todo.cipher_commands = true,
            Opt::CIPHER_ALGORITHMS => todo.cipher_algorithms = true,
            Opt::ENCODERS => todo.encoder_algorithms = true,
            Opt::DECODERS => todo.decoder_algorithms = true,
            Opt::KEYMANAGERS => todo.keymanager_algorithms = true,
            Opt::SKEYMANAGERS => todo.skeymanager_algorithms = true,
            Opt::SIGNATURE_ALGORITHMS => todo.signature_algorithms = true,
            Opt::TLS_SIGNATURE_ALGORITHMS => todo.tls_signature_algorithms = true,
            Opt::KEYEXCHANGE_ALGORITHMS => todo.keyexchange_algorithms = true,
            Opt::KEM_ALGORITHMS => todo.kem_algorithms = true,
            Opt::TLS_GROUPS => todo.tls_groups = true,
            Opt::ALL_TLS_GROUPS => {
                all_tls_groups = true;
                todo.tls_groups = true;
            }
            Opt::TLS1_2 => tls_version = TLS1_2_VERSION,
            Opt::TLS1_3 => tls_version = TLS1_3_VERSION,
            Opt::ASYM_CIPHER_ALGORITHMS => todo.asym_cipher_algorithms = true,
            Opt::PK_ALGORITHMS => todo.pk_algorithms = true,
            Opt::PK_METHOD => todo.pk_method = true,
            Opt::STORE_LOADERS => todo.store_loaders = true,
            Opt::PROVIDER_INFO => todo.provider_info = true,
            Opt::ENGINES => todo.engines = true,
            Opt::DISABLED => todo.disabled = true,
            Opt::OBJECTS => todo.objects = true,
            Opt::OPTIONS => options_for_command(p.arg()),
            Opt::VERBOSE => l.verbose = true,
            Opt::SELECT_NAME => l.select = Some(p.arg().to_owned()),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
        done = true;
    }
    if !p.check_rest_arg(None) {
        return usage();
    }

    // A newline between two listings.
    let mut printed = false;
    let mut next = || {
        if printed {
            out!("\n");
        }
        printed = true;
    };
    if todo.commands {
        next();
        list_type(FuncType::General, one);
    }
    if todo.all_algorithms {
        next();
        out!("Digests:\n");
        l.digests(" ");
        out!("\nSymmetric Ciphers:\n");
        l.ciphers(" ");
        out!("\n");
        l.kdfs();
        out!("\n");
        l.macs();
        out!("\nProvided Asymmetric Encryption:\n");
        l.asymciphers();
        out!("\nProvided Key Exchange:\n");
        l.keyexchanges();
        out!("\nProvided Signatures:\n");
        l.signatures();
        out!("\nProvided Key encapsulation:\n");
        l.kems();
        out!("\nProvided Key managers:\n");
        l.keymanagers();
        out!("\n");
        l.encoders();
        out!("\n");
        l.decoders();
        out!("\n");
        l.store_loaders();
    }
    if todo.random_instances {
        next();
        l.display_random("primary", Instance::Primary);
        l.display_random("public", Instance::Public);
        l.display_random("private", Instance::Private);
    }
    if todo.random_generators {
        next();
        l.random_generators();
    }
    if todo.digest_commands {
        next();
        list_type(FuncType::Md, one);
    }
    if todo.digest_algorithms {
        next();
        l.digests("");
    }
    if todo.kdf_algorithms {
        next();
        l.kdfs();
    }
    if todo.mac_algorithms {
        next();
        l.macs();
    }
    if todo.cipher_commands {
        next();
        list_type(FuncType::Cipher, one);
    }
    if todo.cipher_algorithms {
        next();
        l.ciphers("");
    }
    if todo.encoder_algorithms {
        next();
        l.encoders();
    }
    if todo.decoder_algorithms {
        next();
        l.decoders();
    }
    if todo.keymanager_algorithms {
        next();
        l.keymanagers();
    }
    if todo.skeymanager_algorithms {
        next();
        l.skeymanagers();
    }
    if todo.signature_algorithms {
        next();
        l.signatures();
    }
    if todo.tls_signature_algorithms {
        next();
        tls_signatures();
    }
    if todo.asym_cipher_algorithms {
        next();
        l.asymciphers();
    }
    if todo.keyexchange_algorithms {
        next();
        l.keyexchanges();
    }
    if todo.kem_algorithms {
        next();
        l.kems();
    }
    if todo.tls_groups {
        next();
        tls_groups(tls_version, all_tls_groups);
    }
    if todo.pk_algorithms {
        next();
        l.pkey();
    }
    if todo.pk_method {
        next();
        l.pkey_meth();
    }
    if todo.store_loaders {
        next();
        l.store_loaders();
    }
    if todo.provider_info {
        next();
        l.provider_info();
    }
    if todo.engines {
        next();
        out!("Engines:\n");
        for id in alg::engine_ids() {
            out!("{id}\n");
        }
    }
    if todo.disabled {
        next();
        disabled();
    }
    if todo.objects {
        next();
        objects();
    }
    if !done {
        return usage();
    }
    0
}
