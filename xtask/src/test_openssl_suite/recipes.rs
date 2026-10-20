//! The whole upstream test tree (`cargo xtask test-openssl-suite --all [recipe...]`): every
//! recipe in `test/recipes/`, run by upstream's own `test/run_tests.pl` on the reference and
//! then on rustyssl (TEST_PLAN.md, layer L6; milestone M6's "at least 98% of eligible upstream
//! tests").
//!
//! The reference's source is configured as the reference is and built whole, the test programs
//! upstream links with the static libraries relinked with the shared ones, into
//! `target/ref-suite/openssl-<version>-all/`. Its `util/shlib_wrap.sh`, through which every
//! recipe runs `apps/openssl` and the test programs, takes two variables: `RUSTYSSL_LIBDIR`
//! points the dynamic loader at another build of the libraries, and `RUSTYSSL_MODULES` replaces
//! the tree's provider modules (the default `OPENSSL_MODULES`) with that build's. So each
//! recipe runs twice in the same tree, with the same programs, and only the libraries differ.
//!
//! A recipe's results are its top-level TAP subtests. What counts ("eligible") is a subtest
//! that passes on the reference and isn't excluded; it passes when it passes on rustyssl too.
//! Excluded, and reported apart:
//! - recipes `tests/openssl-suite/recipes.txt` skips (`skip` lines, with reasons: FIPS, QUIC,
//!   features the default build leaves out, ...);
//! - subtests that run a test program needing libcrypto's or libssl's internal functions (it
//!   imports symbols the reference exports and rustyssl doesn't: found from the programs
//!   themselves, so it can't load on another library by construction), and subtests the list
//!   names (`internal` lines: programs that read the libraries' private structures);
//! - subtests skipped on both, and subtests that fail on the reference itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Build;
use crate::targets::host;
use crate::util::{Result, fresh_dir, run_logged, target_dir};
use crate::vendor::CONFIGURE_OPTIONS;

/// How long one recipe may run on one library.
const TIMEOUT: Duration = Duration::from_secs(1800);

/// Marks a finished build; holds the inputs it was built from.
const STAMP: &str = ".rustyssl-build";

/// The list of exclusions.
const LIST: &str = "tests/openssl-suite/recipes.txt";

/// `util/shlib_wrap.sh.in`'s change: the libraries and modules of another build.
const WRAP_FROM: &str = "LIBSSLSO=\"${THERE}/{- platform->sharedlib('libssl') -}\"\n";
const WRAP_TO: &str = "LIBSSLSO=\"${THERE}/{- platform->sharedlib('libssl') -}\"\n\
# rustyssl: RUSTYSSL_LIBDIR runs the program on another build of the libraries, and\n\
# RUSTYSSL_MODULES replaces this tree's provider modules (the default OPENSSL_MODULES) with\n\
# that build's.\n\
LIBDIR=\"${THERE}\"\n\
if [ -n \"$RUSTYSSL_LIBDIR\" ]; then\n\
\tLIBDIR=\"$RUSTYSSL_LIBDIR\"\n\
\tLIBCRYPTOSO=\"$RUSTYSSL_LIBDIR/`basename \"$LIBCRYPTOSO\"`\"\n\
\tLIBSSLSO=\"$RUSTYSSL_LIBDIR/`basename \"$LIBSSLSO\"`\"\n\
\tif [ -n \"$RUSTYSSL_MODULES\" ]; then\n\
\t\tcase \"`cd \"$OPENSSL_MODULES\" 2>/dev/null && pwd -P`\" in\n\
\t\t\"`cd \"${THERE}/providers\" 2>/dev/null && pwd -P`\") OPENSSL_MODULES=\"$RUSTYSSL_MODULES\"; export OPENSSL_MODULES ;;\n\
\t\tesac\n\
\tfi\n\
fi\n";

/// `util/shlib_wrap.sh.in`'s second change: `RUSTYSSL_CLI` runs another `openssl` tool in
/// place of the tree's `apps/openssl` (`--cli ours`, ADR 0007, section 4). The recipes find the
/// tool through `bldtop_file("apps", "openssl")`, and every run of it goes through here.
const CLI_FROM: &str = "cmd=\"$1\"; [ -x \"$cmd\" ] || cmd=\"$cmd${EXE_EXT}\"\n";
const CLI_TO: &str = r#"# rustyssl: RUSTYSSL_CLI replaces this tree's apps/openssl.
if [ -n "$RUSTYSSL_CLI" ] && [ "$(basename "$1")" = openssl ] \
	&& [ "$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" = "$(cd "${THERE}/apps" 2>/dev/null && pwd -P)" ]; then
	shift
	set -- "$RUSTYSSL_CLI" "$@"
fi
cmd="$1"; [ -x "$cmd" ] || cmd="$cmd${EXE_EXT}"
"#;

/// The patches to the reference's source, after the libssl and crypto builds' own.
fn patches(src: &Path, base: &[Build]) -> Result<Vec<(&'static str, String, String)>> {
    let mut out: Vec<(&'static str, String, String)> = base
        .iter()
        .flat_map(|b| b.patches.iter().cloned())
        .collect();
    out.push((
        "util/shlib_wrap.sh.in",
        WRAP_FROM.to_owned(),
        WRAP_TO.to_owned(),
    ));
    out.push((
        "util/shlib_wrap.sh.in",
        CLI_FROM.to_owned(),
        CLI_TO.to_owned(),
    ));
    for (dir, lib) in [
        ("LD_LIBRARY_PATH", "# Linux, ELF HP-UX"),
        ("DYLD_LIBRARY_PATH", "# MacOS X"),
    ] {
        out.push((
            "util/shlib_wrap.sh.in",
            format!("{dir}=\"${{THERE}}:${dir}\"\t{lib}"),
            format!("{dir}=\"${{LIBDIR}}:${dir}\"\t{lib}"),
        ));
    }
    // Every program upstream links with the static libraries is relinked with the shared ones,
    // so that it runs on either; those that need internal functions are found afterwards.
    for file in ["test/build.info", "fuzz/build.info"] {
        let text = fs::read_to_string(src.join(file))?;
        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("DEPEND["))
        {
            let relinked = line
                .replace("../libcrypto.a", "../libcrypto")
                .replace("../libssl.a", "../libssl");
            if relinked != line {
                out.push((file, format!("{line}\n"), format!("{relinked}\n")));
            }
        }
    }
    Ok(out)
}

/// Builds the whole tree unless an up-to-date build exists, and returns it.
fn ensure_tree(root: &Path, version: &str, reference: &Path, base: &[Build]) -> Result<PathBuf> {
    let (_, target) = host()?;
    let tree = target_dir(root)
        .join("ref-suite")
        .join(format!("openssl-{version}-all"));
    let mut options: Vec<&str> = CONFIGURE_OPTIONS.to_vec();
    options.push("-g");
    let src_ref = reference.join("src");
    let patches = patches(&src_ref, base)?;
    let inputs = format!(
        "version = {version}\ntarget = {}\noptions = {}\npatches = {patches:?}\n",
        target.configure,
        options.join(" "),
    );
    if fs::read_to_string(tree.join(STAMP)).is_ok_and(|built| built == inputs) {
        return Ok(tree);
    }
    fresh_dir(&tree)?;
    fs::remove_dir(&tree)?;
    let log = target_dir(root).join("xtask/ref-suite-all.log");
    if let Some(dir) = log.parent() {
        fs::create_dir_all(dir)?;
    }
    let _ = fs::remove_file(&log);
    let mut copy = Command::new("cp");
    copy.arg("-R").arg(&src_ref).arg(&tree);
    run_logged(&mut copy, &log)?;
    for (file, from, to) in &patches {
        let path = tree.join(file);
        let text = fs::read_to_string(&path)?;
        if !text.contains(from.as_str()) {
            if !to.is_empty() && text.contains(to.as_str()) {
                continue;
            }
            return Err(format!("{file} has no `{}`", from.trim_end()).into());
        }
        fs::write(&path, text.replacen(from.as_str(), to, 1))?;
    }
    println!(
        "Building upstream OpenSSL {version} whole for {} (log: {})...",
        target.configure,
        log.display()
    );
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut configure = Command::new("perl");
    configure
        .arg("Configure")
        .arg(target.configure)
        .args(&options)
        .arg(format!("--prefix={}", reference.display()))
        .arg("--libdir=lib")
        .current_dir(&tree)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut configure, &log)?;
    let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    // `-k`: a program that needs functions the shared library doesn't export (Linux) doesn't
    // link, and is then missing; the rest of the tree still builds.
    let mut make = Command::new("make");
    make.arg(format!("-j{jobs}"))
        .arg("-k")
        .current_dir(&tree)
        .env_clear()
        .env("PATH", &path);
    if let Err(e) = run_logged(&mut make, &log) {
        println!("  some programs didn't build ({e}); their subtests fail on both libraries");
    }
    fs::write(tree.join(STAMP), inputs)?;
    Ok(tree)
}

/// The dynamic symbols a library defines.
fn exported(lib: &Path) -> Result<BTreeSet<String>> {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-gU"]
    } else {
        &["-D", "--defined-only"]
    };
    let out = Command::new("nm").args(args).arg(lib).output()?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| s.split('@').next().unwrap_or(s).to_owned())
        .collect())
}

/// The tree's programs (`test/`, `fuzz/`, `apps/`) that import functions of the reference's
/// libraries rustyssl's don't export, with those functions.
fn internal_programs(tree: &Path, ours: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    let ext = if cfg!(target_os = "macos") {
        "3.dylib"
    } else {
        "so.3"
    };
    let mut theirs = BTreeSet::new();
    let mut mine = BTreeSet::new();
    for lib in ["libcrypto", "libssl"] {
        theirs.extend(exported(&tree.join(format!("{lib}.{ext}")))?);
        mine.extend(exported(&ours.join(format!("{lib}.{ext}")))?);
    }
    let missing: BTreeSet<&String> = theirs.difference(&mine).collect();
    let undefined: &[&str] = if cfg!(target_os = "macos") {
        &["-u"]
    } else {
        &["-D", "--undefined-only"]
    };
    let mut out = BTreeMap::new();
    for dir in ["test", "fuzz", "apps"] {
        let Ok(entries) = fs::read_dir(tree.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains('.') || !path.is_file() {
                continue;
            }
            let head = fs::read(&path)
                .ok()
                .and_then(|b| b.get(..4).map(<[u8]>::to_vec));
            let binary = matches!(
                head.as_deref(),
                Some([0xcf, 0xfa, 0xed, 0xfe] | [0x7f, b'E', b'L', b'F'])
            );
            if !binary {
                continue;
            }
            let nm = Command::new("nm").args(undefined).arg(&path).output()?;
            let need: Vec<String> = String::from_utf8_lossy(&nm.stdout)
                .lines()
                .filter_map(|l| l.split_whitespace().last())
                .map(|s| s.split('@').next().unwrap_or(s).to_owned())
                .filter(|s| missing.contains(s))
                .collect();
            if !need.is_empty() {
                out.insert(format!("{dir}/{name}"), need);
            }
        }
    }
    Ok(out)
}

/// `tests/openssl-suite/recipes.txt`: recipes not run, and subtests that read the libraries'
/// private structures.
struct List {
    skip: BTreeMap<String, String>,
    /// recipe -> subtest numbers (empty: all) and the reason.
    internal: BTreeMap<String, (BTreeSet<usize>, String)>,
}

impl List {
    fn load(root: &Path) -> Result<List> {
        let text = fs::read_to_string(root.join(LIST))?;
        let mut list = List {
            skip: BTreeMap::new(),
            internal: BTreeMap::new(),
        };
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.splitn(3, ' ');
            let kind = words.next().unwrap_or_default();
            let recipe = words.next().ok_or(format!("{LIST}:{}: no recipe", n + 1))?;
            let rest = words.next().unwrap_or_default().trim();
            match kind {
                "skip" => {
                    list.skip.insert(recipe.to_owned(), rest.to_owned());
                }
                "internal" => {
                    // `internal <recipe> [#n ...] <reason>`
                    let mut numbers = BTreeSet::new();
                    let mut reason = rest;
                    while let Some(r) = reason.strip_prefix('#') {
                        let (num, tail) = r.split_once(' ').unwrap_or((r, ""));
                        numbers.insert(num.parse::<usize>()?);
                        reason = tail.trim_start();
                    }
                    list.internal
                        .insert(recipe.to_owned(), (numbers, reason.to_owned()));
                }
                _ => return Err(format!("{LIST}:{}: unknown `{kind}`", n + 1).into()),
            }
        }
        Ok(list)
    }
}

/// One subtest's result on one library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Pass,
    Fail,
    Skip,
    /// No result: the recipe stopped before it, or timed out.
    Missing,
}

/// One recipe's run on one library: each subtest's status and the output that led to it.
struct Run {
    plan: usize,
    subtests: BTreeMap<usize, (Status, String)>,
    /// The whole recipe skipped itself (`skipped: reason`).
    skipped: Option<String>,
    timed_out: bool,
}

/// Parses `run_tests.pl`'s verbose output for `file` (`NN-test_x.t`).
fn parse(text: &str, file: &str) -> Run {
    let mut run = Run {
        plan: 0,
        subtests: BTreeMap::new(),
        skipped: None,
        timed_out: false,
    };
    let header = format!("{file} ..");
    let Some(start) = text.find(&header) else {
        return run;
    };
    let body = text.get(start..).unwrap_or_default();
    if let Some(first) = body.lines().next()
        && let Some(reason) = first.split_once("skipped: ").map(|(_, r)| r)
    {
        run.skipped = Some(reason.trim().to_owned());
        return run;
    }
    let mut block = String::new();
    for line in body.lines().skip(1) {
        if let Some(n) = line.strip_prefix("1..")
            && let Ok(n) = n.trim().parse()
            && run.plan == 0
        {
            run.plan = n;
            continue;
        }
        let (status, rest) = if let Some(r) = line.strip_prefix("ok ") {
            (Status::Pass, r)
        } else if let Some(r) = line.strip_prefix("not ok ") {
            (Status::Fail, r)
        } else {
            block.push_str(line);
            block.push('\n');
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let Ok(n) = digits.parse::<usize>() else {
            block.push_str(line);
            block.push('\n');
            continue;
        };
        let status = if rest.to_ascii_lowercase().contains("# skip") {
            Status::Skip
        } else {
            status
        };
        block.push_str(line);
        run.subtests.insert(n, (status, std::mem::take(&mut block)));
    }
    run
}

/// Runs recipe `name` (`test_x`) on the reference, or with `ours` on rustyssl.
fn run_recipe(
    tree: &Path,
    name: &str,
    file: &str,
    ours: Option<&Path>,
    cli: Option<&Path>,
) -> Result<Run> {
    let side = if ours.is_some() { "ours" } else { "ref" };
    let results = tree.join(format!("test-runs-{side}"));
    fs::create_dir_all(&results)?;
    let out_path = results.join(format!("{name}.log"));
    let out = fs::File::create(&out_path)?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut cmd = Command::new("perl");
    cmd.arg("test/run_tests.pl")
        .arg(name)
        .current_dir(tree)
        .env_clear()
        .env("PATH", &path)
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("SRCTOP", tree)
        .env("BLDTOP", tree)
        .env("PERL", "perl")
        .env("V", "1")
        .env("RESULT_D", &results);
    if let Some(lib) = ours {
        cmd.env("RUSTYSSL_LIBDIR", lib)
            .env("RUSTYSSL_MODULES", crate::test_c::modules_of(lib));
        if let Some(cli) = cli {
            cmd.env("RUSTYSSL_CLI", cli);
        }
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out)
        .spawn()?;
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            child.wait()?;
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let text = String::from_utf8_lossy(&fs::read(&out_path)?).into_owned();
    let mut run = parse(&text, file);
    run.timed_out = timed_out;
    Ok(run)
}

/// A subtest's verdict.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Verdict {
    Pass,
    Fail,
    Internal,
    SkippedBoth,
    ReferenceFails,
}

struct Recipe {
    name: String,
    verdicts: BTreeMap<usize, (Verdict, String)>,
    note: Option<String>,
}

fn judge(
    name: &str,
    theirs: &Run,
    ours: &Run,
    list: &List,
    internals: &BTreeMap<String, Vec<String>>,
) -> Recipe {
    let mut recipe = Recipe {
        name: name.to_owned(),
        verdicts: BTreeMap::new(),
        note: None,
    };
    if let Some(reason) = &theirs.skipped {
        recipe.note = Some(format!("skipped on the reference: {reason}"));
        return recipe;
    }
    let listed = list.internal.get(name);
    let n = theirs.plan.max(ours.plan).max(
        theirs
            .subtests
            .keys()
            .chain(ours.subtests.keys())
            .copied()
            .max()
            .unwrap_or(0),
    );
    for i in 1..=n {
        let (t, t_text) = theirs
            .subtests
            .get(&i)
            .map_or((Status::Missing, ""), |(s, b)| (*s, b.as_str()));
        let (o, o_text) = ours
            .subtests
            .get(&i)
            .map_or((Status::Missing, ""), |(s, b)| (*s, b.as_str()));
        let uses_internal = internals.keys().any(|p| {
            [t_text, o_text]
                .iter()
                .any(|b| b.contains(&format!("/{p} ")) || b.contains(&format!("/{p}\n")))
        });
        let named = listed.is_some_and(|(nums, _)| nums.is_empty() || nums.contains(&i));
        let verdict = if named || uses_internal {
            Verdict::Internal
        } else if t == Status::Skip && o == Status::Skip {
            Verdict::SkippedBoth
        } else if t != Status::Pass {
            Verdict::ReferenceFails
        } else if o == Status::Pass {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        let detail = if verdict == Verdict::Fail {
            let mut d = o_text.to_owned();
            if o == Status::Missing {
                d = if ours.timed_out {
                    "no result: the recipe timed out".to_owned()
                } else {
                    "no result: the recipe stopped before it".to_owned()
                };
            } else if o == Status::Skip {
                d = format!("skipped on rustyssl only:\n{d}");
            }
            d
        } else {
            String::new()
        };
        recipe.verdicts.insert(i, (verdict, detail));
    }
    recipe
}

/// Runs the recipes `args` names (all, without any) and writes the report. With `cli`, the
/// runs on rustyssl use that `openssl` tool in place of the tree's (`--cli ours`).
pub fn run(
    root: &Path,
    version: &str,
    reference: &Path,
    ours: &Path,
    cli: Option<&Path>,
    base: &[Build],
    args: &[String],
) -> Result {
    let list = List::load(root)?;
    let tree = ensure_tree(root, version, reference, base)?;
    let internals = internal_programs(&tree, ours)?;
    let mut recipes: Vec<(String, String)> = Vec::new();
    for entry in fs::read_dir(tree.join("test/recipes"))? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        let Some(stem) = file.strip_suffix(".t") else {
            continue;
        };
        let name = stem.split_once('-').map_or(stem, |(_, n)| n).to_owned();
        if args.is_empty() || args.iter().any(|a| *a == name || *a == file) {
            recipes.push((name, file));
        }
    }
    recipes.sort_by(|a, b| a.1.cmp(&b.1));
    if recipes.is_empty() {
        return Err("no recipes selected".into());
    }
    let (skipped, todo): (Vec<_>, Vec<_>) =
        recipes.iter().partition(|(n, _)| list.skip.contains_key(n));
    println!(
        "Running {} upstream recipes, each on the reference and then on rustyssl{} ({} skipped by {LIST}; {} programs need internal functions)...",
        todo.len(),
        cli.map(|c| format!(" with {}", c.display()))
            .unwrap_or_default(),
        skipped.len(),
        internals.len()
    );
    let next = AtomicUsize::new(0);
    let done: Mutex<Vec<Recipe>> = Mutex::new(Vec::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let jobs = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .div_ceil(2);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((name, file)) = todo.get(i) else {
                        break;
                    };
                    let both = run_recipe(&tree, name, file, None, None).and_then(|t| {
                        run_recipe(&tree, name, file, Some(ours), cli).map(|o| (t, o))
                    });
                    match both {
                        Ok((t, o)) => {
                            let r = judge(name, &t, &o, &list, &internals);
                            let fails =
                                r.verdicts.values().filter(|v| v.0 == Verdict::Fail).count();
                            println!(
                                "{} {name}: {} subtests{}",
                                if fails == 0 { "PASS" } else { "FAIL" },
                                r.verdicts.len(),
                                if fails == 0 {
                                    String::new()
                                } else {
                                    format!(", {fails} fail on rustyssl only")
                                }
                            );
                            if let Ok(mut d) = done.lock() {
                                d.push(r);
                            }
                        }
                        Err(e) => {
                            if let Ok(mut errs) = errors.lock() {
                                errs.push(format!("{name}: {e}"));
                            }
                        }
                    }
                }
            });
        }
    });
    let errors = errors.into_inner().map_err(|_| "a runner panicked")?;
    if !errors.is_empty() {
        return Err(errors.join("\n").into());
    }
    let mut done = done.into_inner().map_err(|_| "a runner panicked")?;
    done.sort_by(|a, b| a.name.cmp(&b.name));
    let report = write_report(root, &done, &skipped, &list, &internals, cli)?;
    let count = |v: Verdict| -> usize {
        done.iter()
            .map(|r| r.verdicts.values().filter(|x| x.0 == v).count())
            .sum()
    };
    let (pass, fail) = (count(Verdict::Pass), count(Verdict::Fail));
    let eligible = pass + fail;
    let rate = if eligible == 0 {
        0.0
    } else {
        f64::from(u32::try_from(pass).unwrap_or(u32::MAX)) * 100.0
            / f64::from(u32::try_from(eligible).unwrap_or(u32::MAX))
    };
    println!(
        "{eligible} eligible upstream subtests: {pass} pass on rustyssl ({rate:.2}%), {fail} fail; {} internal, {} skipped on both, {} fail on the reference (report: {})",
        count(Verdict::Internal),
        count(Verdict::SkippedBoth),
        count(Verdict::ReferenceFails),
        report.display()
    );
    if fail == 0 {
        Ok(())
    } else {
        Err(format!("{fail} of {eligible} eligible upstream subtests fail on rustyssl").into())
    }
}

fn write_report(
    root: &Path,
    done: &[Recipe],
    skipped: &[&(String, String)],
    list: &List,
    internals: &BTreeMap<String, Vec<String>>,
    cli: Option<&Path>,
) -> Result<PathBuf> {
    let mut md = String::from("# The upstream test tree on rustyssl\n\n");
    if let Some(cli) = cli {
        writeln!(
            md,
            "With `--cli ours`: the runs on rustyssl use `{}` in place of the tree's \
             `apps/openssl`.\n",
            cli.display()
        )?;
    }
    writeln!(
        md,
        "Written by `cargo xtask test-openssl-suite --all`. Each recipe of the reference's \
         `test/recipes/` runs through `test/run_tests.pl` on the reference, then on rustyssl \
         (the same programs; only the libraries differ). A subtest is eligible when it passes on \
         the reference and isn't excluded.\n"
    )?;
    md.push_str("## Per recipe\n\n| recipe | eligible | pass | fail | internal | skipped | reference fails |\n|---|---:|---:|---:|---:|---:|---:|\n");
    for r in done {
        let c = |v: Verdict| r.verdicts.values().filter(|x| x.0 == v).count();
        let (p, f) = (c(Verdict::Pass), c(Verdict::Fail));
        writeln!(
            md,
            "| {}{} | {} | {p} | {f} | {} | {} | {} |",
            r.name,
            r.note
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default(),
            p + f,
            c(Verdict::Internal),
            c(Verdict::SkippedBoth),
            c(Verdict::ReferenceFails)
        )?;
    }
    md.push_str("\n## Failures on rustyssl\n\n");
    for r in done {
        for (i, (v, detail)) in &r.verdicts {
            if *v != Verdict::Fail {
                continue;
            }
            let tail: Vec<&str> = detail.lines().rev().take(25).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            writeln!(md, "### {} #{i}\n\n```\n{}\n```\n", r.name, tail.join("\n"))?;
        }
    }
    md.push_str("## Not run\n\n");
    for (name, _) in skipped {
        writeln!(
            md,
            "- {name}: {}",
            list.skip.get(name).map_or("", String::as_str)
        )?;
    }
    md.push_str("\n## Listed as reading private structures\n\n");
    for (name, (nums, reason)) in &list.internal {
        let which = if nums.is_empty() {
            "all".to_owned()
        } else {
            nums.iter()
                .map(|n| format!("#{n}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        writeln!(md, "- {name} {which}: {reason}")?;
    }
    md.push_str("\n## Programs that need internal functions\n\n");
    for (program, symbols) in internals {
        let shown: Vec<&str> = symbols
            .iter()
            .take(4)
            .map(|s| s.trim_start_matches('_'))
            .collect();
        writeln!(
            md,
            "- {program}: {}{}",
            shown.join(", "),
            if symbols.len() > 4 { ", ..." } else { "" }
        )?;
    }
    let path = target_dir(root).join("upstream-report.md");
    fs::write(&path, md)?;
    Ok(path)
}
