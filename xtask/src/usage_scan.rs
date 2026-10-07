//! `cargo xtask usage-scan [--jobs N] [--limit N]`: ranks rustssl's exports by how many
//! distribution packages import them, so breadth phases implement the most-used functions
//! first (IMPLEMENTATION_PLAN.md, step 0.10). It writes `docs/symbol-usage.md`.
//!
//! For each distribution in `SOURCES`, it reads the package index, picks the amd64 packages
//! that depend on OpenSSL's libraries, downloads each one over HTTPS, and checks it against the
//! index's SHA-256. Then it reads which functions every ELF file in the package imports from
//! `libssl.so.3` and `libcrypto.so.3` (`crate::elf`). Packages are untrusted: they're parsed in
//! memory and never unpacked to disk or run (`archive.rs`). The index itself is trusted only
//! as far as HTTPS goes; its signature isn't checked, since the output is statistics.
//!
//! Each package's imports are cached in `target/xtask/usage-scan/imports-v<N>/<sha256>`, and
//! the package is deleted once it's read. A rerun therefore downloads only packages that
//! changed. A full scan downloads about 5 GB. `--limit N` scans the first N packages of each
//! distribution, as a quick trial, and writes its report under `target/` instead of `docs/`.
//!
//! Needs `curl`, `xz`, and `zstd`.

mod archive;
mod index;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::codegen::exports::{LIBRARIES, parse_version_script};
use crate::elf::{self, Import};
use crate::targets::{OPENSSL_SERIES, TARGETS};
use crate::util::{Result, fresh_dir, run_output, sha256_file, target_dir, workspace_root};
use index::Package;

const REPORT: &str = "docs/symbol-usage.md";
const USAGE: &str = "usage: cargo xtask usage-scan [--jobs N] [--limit N]";

/// Bump when what's read from a package changes, so cached results are read again.
const CACHE_VERSION: u32 = 1;

/// The sonames whose imports are counted.
const SONAMES: &[&str] = &["libssl.so.3", "libcrypto.so.3"];

/// The Debian and Ubuntu package holding both libraries (`libssl3` before the 64-bit `time_t`
/// transition renamed it).
const DEB_OPENSSL: &[&str] = &["libssl3t64", "libssl3"];

enum Format {
    Deb {
        suite: &'static str,
        components: &'static [&'static str],
    },
    Rpm,
}

struct Source {
    /// Short name: the report's column and the progress output.
    key: &'static str,
    label: &'static str,
    /// The repository root that package paths are relative to.
    base: &'static str,
    format: Format,
}

/// Current releases that ship OpenSSL 3.5, the series rustssl targets first.
const SOURCES: &[Source] = &[
    Source {
        key: "Debian",
        label: "Debian 13 (trixie)",
        base: "https://deb.debian.org/debian",
        format: Format::Deb {
            suite: "trixie",
            components: &["main"],
        },
    },
    Source {
        key: "Ubuntu",
        label: "Ubuntu 26.04 LTS (resolute)",
        base: "https://archive.ubuntu.com/ubuntu",
        format: Format::Deb {
            suite: "resolute",
            components: &["main", "universe"],
        },
    },
    Source {
        key: "Fedora",
        label: "Fedora 44",
        base: "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os",
        format: Format::Rpm,
    },
];

/// One distribution's packages, as found in its index.
struct Listing {
    openssl: String,
    packages: Vec<Package>,
}

/// What scanning one package found.
struct Scanned {
    source: usize,
    package: String,
    imports: std::result::Result<BTreeSet<Import>, String>,
}

pub fn run(args: &[String]) -> Result {
    let (jobs, limit) = parse_args(args)?;
    let root = workspace_root();
    let work = target_dir(&root).join("xtask/usage-scan");
    let cache = work.join(format!("imports-v{CACHE_VERSION}"));
    let scratch = work.join("scratch");
    fresh_dir(&scratch)?;
    fs::create_dir_all(&cache)?;

    let mut listings = Vec::new();
    for source in SOURCES {
        let listing = list(source, &scratch)?;
        println!(
            "{}: {} packages depend on OpenSSL {}",
            source.label,
            listing.packages.len(),
            listing.openssl
        );
        listings.push(listing);
    }

    // Interleaved, so the parallel downloads are spread over the mirrors.
    let longest = listings.iter().map(|l| l.packages.len()).max().unwrap_or(0);
    let queue: Vec<(usize, &Package)> = (0..longest.min(limit.unwrap_or(usize::MAX)))
        .flat_map(|n| {
            listings
                .iter()
                .enumerate()
                .filter_map(move |(i, listing)| listing.packages.get(n).map(|p| (i, p)))
        })
        .collect();
    let scanned = scan_all(&queue, jobs, &cache, &scratch)?;
    let exports = exports(&root)?;
    let report = render(&listings, &scanned, &exports, &today())?;
    let path = match limit {
        Some(_) => work.join("symbol-usage.md"),
        None => root.join(REPORT),
    };
    fs::write(&path, report)?;
    println!("Wrote {}", path.display());
    let failed = scanned.iter().filter(|s| s.imports.is_err()).count();
    if failed > 0 {
        println!("{failed} package(s) couldn't be scanned; the report lists them");
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(usize, Option<usize>)> {
    // At most 8 by default, to go easy on the mirrors.
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let mut limit = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value: usize = args.next().ok_or(USAGE)?.parse()?;
        match arg.as_str() {
            "--jobs" if value > 0 => jobs = value,
            "--limit" => limit = Some(value),
            _ => return Err(USAGE.into()),
        }
    }
    Ok((jobs, limit))
}

/// Downloads a distribution's index and lists the packages that depend on OpenSSL, sorted by
/// name.
fn list(source: &Source, scratch: &Path) -> Result<Listing> {
    let mut listing = match source.format {
        Format::Deb { suite, components } => {
            let mut packages = Vec::new();
            let mut openssl = None;
            for component in components {
                let url = format!(
                    "{}/dists/{suite}/{component}/binary-amd64/Packages.xz",
                    source.base
                );
                let file = scratch.join(format!("{}-{component}-Packages.xz", source.key));
                fetch(&url, &file)?;
                let text = decompress_text("xz", &file)?;
                packages.extend(index::debian(&text, DEB_OPENSSL)?);
                openssl = openssl.or_else(|| index::debian_version(&text, "libssl3t64"));
            }
            Listing {
                openssl: openssl.ok_or("no libssl3t64 package in the index")?,
                packages,
            }
        }
        Format::Rpm => {
            let repomd = scratch.join(format!("{}-repomd.xml", source.key));
            fetch(&format!("{}/repodata/repomd.xml", source.base), &repomd)?;
            let (path, sha256) = index::fedora_primary(&fs::read_to_string(&repomd)?)?;
            let file = scratch.join(format!(
                "{}-{}",
                source.key,
                path.rsplit('/').next().unwrap_or("primary")
            ));
            fetch(&format!("{}/{path}", source.base), &file)?;
            check_sha256(&file, &sha256)?;
            let tool = match path.rsplit('.').next() {
                Some("zst") => "zstd",
                Some("xz") => "xz",
                Some("gz") => "gzip",
                _ => return Err(format!("unknown compression: {path}").into()),
            };
            let text = decompress_text(tool, &file)?;
            Listing {
                openssl: index::fedora_version(&text, "openssl-libs", "x86_64")
                    .ok_or("no openssl-libs package in the index")?,
                packages: index::fedora(&text, "x86_64", SONAMES)?,
            }
        }
    };
    listing.packages.sort_by(|a, b| a.name.cmp(&b.name));
    listing.packages.dedup_by(|a, b| a.name == b.name);
    Ok(listing)
}

/// Downloads `url` to `dest` over HTTPS only, redirects included.
fn fetch(url: &str, dest: &Path) -> Result {
    run_output(
        Command::new("curl")
            .args(["--fail", "--silent", "--show-error", "--location"])
            .args([
                "--retry",
                "3",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
            ])
            .arg("--output")
            .arg(dest)
            .arg(url),
    )
    .map_err(|e| format!("cannot download {url}: {e}"))?;
    Ok(())
}

fn decompress_text(tool: &str, file: &Path) -> Result<String> {
    run_output(Command::new(tool).arg("-dc").arg("--").arg(file))
}

fn check_sha256(file: &Path, expected: &str) -> Result {
    let actual = sha256_file(file)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{}: SHA-256 {actual}, but the index says {expected}",
            file.display()
        )
        .into())
    }
}

/// Scans every queued package on `jobs` threads.
fn scan_all(
    queue: &[(usize, &Package)],
    jobs: usize,
    cache: &Path,
    scratch: &Path,
) -> Result<Vec<Scanned>> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for worker in 0..jobs {
            let (next, done, results) = (&next, &done, &results);
            let scratch = scratch.join(format!("worker-{worker}"));
            scope.spawn(move || {
                while let Some((source, package)) = queue.get(next.fetch_add(1, Ordering::Relaxed))
                {
                    let imports = SOURCES
                        .get(*source)
                        .ok_or_else(|| "no such source".to_owned())
                        .and_then(|s| scan(s, package, cache, &scratch).map_err(|e| e.to_string()));
                    if let Err(e) = &imports {
                        println!("{} {}: {e}", key(*source), package.name);
                    }
                    let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if finished % 100 == 0 || finished == queue.len() {
                        println!("Scanned {finished} of {} packages", queue.len());
                    }
                    if let Ok(mut results) = results.lock() {
                        results.push(Scanned {
                            source: *source,
                            package: package.name.clone(),
                            imports,
                        });
                    }
                }
            });
        }
    });
    let mut scanned = results.into_inner().map_err(|_| "a scan thread panicked")?;
    scanned.sort_by(|a, b| (a.source, &a.package).cmp(&(b.source, &b.package)));
    Ok(scanned)
}

/// The OpenSSL imports of one package, from the cache or by downloading and reading it.
fn scan(
    source: &Source,
    package: &Package,
    cache: &Path,
    scratch: &Path,
) -> Result<BTreeSet<Import>> {
    let cached = cache.join(&package.sha256);
    if let Ok(text) = fs::read_to_string(&cached) {
        return read_cache(&text);
    }
    let download = scratch.with_extension("pkg");
    // Paths are checked to be plain (index.rs); `^` is the one character URLs must escape.
    let url = format!("{}/{}", source.base, package.path.replace('^', "%5E"));
    fetch(&url, &download)?;
    let checked = check_sha256(&download, &package.sha256);
    let data = fs::read(&download);
    fs::remove_file(&download)?;
    checked?;
    let data = data?;

    let mut imports = BTreeSet::new();
    let mut found = |file: &[u8]| imports.extend(elf::imports(file, SONAMES));
    let payload = scratch.with_extension("payload");
    match source.format {
        Format::Deb { .. } => archive::deb_elf_files(&data, &payload, &mut found)?,
        Format::Rpm => archive::rpm_elf_files(&data, &payload, &mut found)?,
    }
    let mut text = String::new();
    for import in &imports {
        writeln!(
            text,
            "{} {} {}",
            import.library, import.name, import.version
        )?;
    }
    let partial = cached.with_extension("partial");
    fs::write(&partial, text)?;
    fs::rename(&partial, &cached)?;
    Ok(imports)
}

fn read_cache(text: &str) -> Result<BTreeSet<Import>> {
    text.lines()
        .map(
            |line| match line.split(' ').collect::<Vec<_>>().as_slice() {
                [library, name, version] => Ok(Import {
                    library: (*library).to_owned(),
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                }),
                _ => Err(format!("bad cache line {line:?}").into()),
            },
        )
        .collect()
}

/// rustssl's exports as (library, function) -> version node, from the vendored export lists.
fn exports(root: &Path) -> Result<BTreeMap<(String, String), String>> {
    let target = TARGETS.first().ok_or("no targets")?;
    let mut exports = BTreeMap::new();
    for library in LIBRARIES {
        let path: PathBuf = root
            .join(format!("abi/openssl-{OPENSSL_SERIES}/config"))
            .join(target.configure)
            .join(format!("{library}.ld"));
        let nodes = parse_version_script(&fs::read_to_string(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for (version, names) in nodes {
            for name in names {
                exports.insert(((*library).to_owned(), name), version.clone());
            }
        }
    }
    Ok(exports)
}

/// The short name of source number `source`.
fn key(source: usize) -> &'static str {
    SOURCES.get(source).map_or("?", |s| s.key)
}

/// `libssl.so.3` -> `libssl`.
fn library_of(soname: &str) -> &str {
    soname.split(".so").next().unwrap_or(soname)
}

/// The scan's numbers, ready to print.
struct Summary<'a> {
    /// (library, function) -> packages importing it, per source.
    counts: BTreeMap<(&'a str, &'a str), Vec<usize>>,
    /// Exports in rank order, most imported first.
    ranking: Vec<((&'a str, &'a str), usize)>,
    /// Imports that aren't rustssl exports at that version: (library, name, version) ->
    /// packages as "Source package".
    unknown: BTreeMap<(&'a str, &'a str, &'a str), BTreeSet<String>>,
}

fn summarize<'a>(
    scanned: &'a [Scanned],
    exports: &'a BTreeMap<(String, String), String>,
) -> Summary<'a> {
    let mut counts: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    let mut unknown: BTreeMap<(&str, &str, &str), BTreeSet<String>> = BTreeMap::new();
    for package in scanned {
        let Ok(imports) = &package.imports else {
            continue;
        };
        let mut functions = BTreeSet::new();
        for import in imports {
            let library = library_of(&import.library);
            let exported = exports
                .get_key_value(&(library.to_owned(), import.name.clone()))
                .filter(|(_, version)| **version == import.version);
            match exported {
                Some(((library, name), _)) => {
                    functions.insert((library.as_str(), name.as_str()));
                }
                None => {
                    unknown
                        .entry((library, &import.name, &import.version))
                        .or_default()
                        .insert(format!("{} {}", key(package.source), package.package));
                }
            }
        }
        for function in functions {
            let entry = counts
                .entry(function)
                .or_insert_with(|| vec![0; SOURCES.len()]);
            if let Some(count) = entry.get_mut(package.source) {
                *count += 1;
            }
        }
    }
    let mut ranking: Vec<((&str, &str), usize)> = counts
        .iter()
        .map(|(function, per_source)| (*function, per_source.iter().sum()))
        .collect();
    ranking.sort_by(|(a, a_total), (b, b_total)| {
        b_total.cmp(a_total).then((a.1, a.0).cmp(&(b.1, b.0)))
    });
    Summary {
        counts,
        ranking,
        unknown,
    }
}

/// For each package that imports anything, the lowest rank N such that implementing the top N
/// functions covers all its imports; `None` if it imports something rustssl doesn't export.
fn needed_ranks(scanned: &[Scanned], summary: &Summary) -> Vec<(usize, Option<usize>)> {
    let rank: BTreeMap<(&str, &str), usize> = summary
        .ranking
        .iter()
        .enumerate()
        .map(|(i, (function, _))| (*function, i + 1))
        .collect();
    scanned
        .iter()
        .filter_map(|package| {
            let imports = package.imports.as_ref().ok().filter(|i| !i.is_empty())?;
            let needed = imports.iter().try_fold(0, |needed: usize, import| {
                rank.get(&(library_of(&import.library), import.name.as_str()))
                    .filter(|_| {
                        !summary.unknown.contains_key(&(
                            library_of(&import.library),
                            import.name.as_str(),
                            import.version.as_str(),
                        ))
                    })
                    .map(|r| needed.max(*r))
            });
            Some((package.source, needed))
        })
        .collect()
}

fn render(
    listings: &[Listing],
    scanned: &[Scanned],
    exports: &BTreeMap<(String, String), String>,
    date: &str,
) -> Result<String> {
    let summary = summarize(scanned, exports);
    let mut out = format!(
        "# Symbol usage\n\n\
         Generated by `cargo xtask usage-scan` on {date}. Don't edit it by hand; rerun the scan to \
         refresh it\n(it downloads about 5 GB, and caches what it read).\n\n\
         Which rustssl exports real software calls. Every amd64 package in these distributions \
         that depends\non OpenSSL's libraries was downloaded, and the imports of its ELF files \
         were read (never run). A\npackage counts once per function, however many of its files \
         import it. Breadth phases implement\nfunctions in this order \
         (IMPLEMENTATION_PLAN.md, step 0.10).\n\n\
         | Distribution | OpenSSL | Packages | Scanned | Importing OpenSSL |\n|---|---|--:|--:|--:|\n"
    );
    for (i, (source, listing)) in SOURCES.iter().zip(listings).enumerate() {
        let of_source: Vec<&Scanned> = scanned.iter().filter(|s| s.source == i).collect();
        let ok = of_source.iter().filter(|s| s.imports.is_ok()).count();
        let importing = of_source
            .iter()
            .filter(|s| s.imports.as_ref().is_ok_and(|i| !i.is_empty()))
            .count();
        writeln!(
            out,
            "| {} | {} | {} | {ok} | {importing} |",
            source.label,
            listing.openssl,
            listing.packages.len()
        )?;
    }
    out.push_str(
        "\n*Importing OpenSSL* counts the packages with an ELF file that imports from libssl or \
         libcrypto. The\nothers depend on the libraries without calling them directly: through \
         another library, or from\nscripts.\n",
    );

    let failed: Vec<&Scanned> = scanned.iter().filter(|s| s.imports.is_err()).collect();
    if !failed.is_empty() {
        out.push_str("\n## Not scanned\n\n| Package | Problem |\n|---|---|\n");
        for package in failed {
            if let Err(problem) = &package.imports {
                writeln!(
                    out,
                    "| {} `{}` | {} |",
                    key(package.source),
                    package.package,
                    problem.replace('|', "\\|").replace('\n', " ")
                )?;
            }
        }
    }

    out.push_str(
        "\n## How far the top functions go\n\n\
         How many packages would have every OpenSSL function they import if rustssl implemented \
         only the\nN most-imported ones:\n\n",
    );
    let keys: Vec<&str> = SOURCES.iter().map(|s| s.key).collect();
    writeln!(out, "| Top N | {} | All |", keys.join(" | "))?;
    writeln!(out, "|--:|{}--:|", "--:|".repeat(SOURCES.len()))?;
    let needed = needed_ranks(scanned, &summary);
    let imported = summary.ranking.len();
    let mut steps: Vec<usize> = [10, 25, 50, 100, 250, 500, 1000, 2000]
        .into_iter()
        .filter(|n| *n < imported)
        .collect();
    steps.push(imported);
    for n in steps {
        let covered = |source: Option<usize>| {
            needed
                .iter()
                .filter(|(s, need)| source.is_none_or(|x| x == *s) && need.is_some_and(|r| r <= n))
                .count()
        };
        let total = |source: Option<usize>| {
            needed
                .iter()
                .filter(|(s, _)| source.is_none_or(|x| x == *s))
                .count()
        };
        let cells: Vec<String> = (0..SOURCES.len())
            .map(Some)
            .chain([None])
            .map(|s| format!("{} of {}", covered(s), total(s)))
            .collect();
        let label = if n == imported {
            format!("{n} (all imported)")
        } else {
            n.to_string()
        };
        writeln!(out, "| {label} | {} |", cells.join(" | "))?;
    }

    out.push_str("\n## Imports rustssl doesn't export\n\n");
    if summary.unknown.is_empty() {
        out.push_str(
            "None: every import matches rustssl's export list in name, library, and version \
             node.\n",
        );
    } else {
        out.push_str(
            "These imports name a function or version node that isn't in the OpenSSL \
             3.5 export list rustssl\nfollows. The packages that use them won't load until \
             it's resolved.\n\n| Import | Library | Packages |\n|---|---|---|\n",
        );
        for ((library, name, version), packages) in &summary.unknown {
            let list: Vec<&str> = packages.iter().map(String::as_str).collect();
            writeln!(
                out,
                "| `{name}@{version}` | {library} | {} |",
                list.join(", ")
            )?;
        }
    }

    writeln!(
        out,
        "\n## Ranking\n\n{imported} of the {} exports are imported by at least one package.\n",
        exports.len()
    )?;
    writeln!(
        out,
        "| Rank | Function | Library | {} | Total |",
        keys.join(" | ")
    )?;
    writeln!(out, "|--:|---|---|{}--:|", "--:|".repeat(SOURCES.len()))?;
    for (rank, ((library, name), total)) in summary.ranking.iter().enumerate() {
        let per_source: Vec<String> = summary
            .counts
            .get(&(*library, *name))
            .map(|c| c.iter().map(usize::to_string).collect())
            .unwrap_or_default();
        writeln!(
            out,
            "| {} | `{name}` | {library} | {} | {total} |",
            rank + 1,
            per_source.join(" | ")
        )?;
    }

    let never: Vec<String> = exports
        .keys()
        .filter(|(library, name)| {
            !summary
                .counts
                .contains_key(&(library.as_str(), name.as_str()))
        })
        .map(|(_, name)| format!("`{name}`"))
        .collect();
    writeln!(
        out,
        "\n## Never imported\n\n<details><summary>{} exports that no scanned package imports\
         </summary>\n\n{}\n\n</details>",
        never.len(),
        never.join(", ")
    )?;
    Ok(out)
}

/// Today's date (UTC) as YYYY-MM-DD.
fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400);
    civil_date(days)
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's algorithm).
fn civil_date(days: u64) -> String {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(59), "1970-03-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_733), "2026-10-07");
    }

    #[test]
    fn arguments() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&args(&["--jobs", "3", "--limit", "5"])).unwrap(),
            (3, Some(5))
        );
        assert!(parse_args(&args(&["--jobs", "0"])).is_err());
        assert!(parse_args(&args(&["--limit"])).is_err());
        assert!(parse_args(&args(&["--other", "1"])).is_err());
    }

    #[test]
    fn cache_round_trip() {
        let text = "libssl.so.3 SSL_new OPENSSL_3.0.0\nlibcrypto.so.3 EVP_MD_fetch OPENSSL_3.0.0\n";
        let imports = read_cache(text).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(read_cache("").unwrap().is_empty());
        assert!(read_cache("one two\n").is_err());
    }

    fn import(library: &str, name: &str, version: &str) -> Import {
        Import {
            library: library.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn ranking_and_coverage() {
        let exports: BTreeMap<(String, String), String> = [
            ("libssl", "SSL_new", "OPENSSL_3.0.0"),
            ("libssl", "SSL_free", "OPENSSL_3.0.0"),
            ("libcrypto", "EVP_MD_fetch", "OPENSSL_3.0.0"),
            ("libcrypto", "BN_new", "OPENSSL_3.0.0"),
        ]
        .into_iter()
        .map(|(l, n, v)| ((l.to_owned(), n.to_owned()), v.to_owned()))
        .collect();
        let package = |source: usize, name: &str, imports: &[(&str, &str, &str)]| Scanned {
            source,
            package: name.to_owned(),
            imports: Ok(imports.iter().map(|(l, n, v)| import(l, n, v)).collect()),
        };
        let scanned = vec![
            package(0, "a", &[("libssl.so.3", "SSL_new", "OPENSSL_3.0.0")]),
            package(
                0,
                "b",
                &[
                    ("libssl.so.3", "SSL_new", "OPENSSL_3.0.0"),
                    ("libcrypto.so.3", "EVP_MD_fetch", "OPENSSL_3.0.0"),
                ],
            ),
            package(1, "a", &[("libssl.so.3", "SSL_new", "OPENSSL_3.0.0")]),
            // An import at a version node rustssl doesn't export it under.
            package(2, "c", &[("libssl.so.3", "SSL_free", "OPENSSL_3.6.0")]),
            package(2, "d", &[]),
            Scanned {
                source: 2,
                package: "broken".to_owned(),
                imports: Err("bad archive".to_owned()),
            },
        ];
        let summary = summarize(&scanned, &exports);
        assert_eq!(
            summary.ranking,
            [
                (("libssl", "SSL_new"), 3),
                (("libcrypto", "EVP_MD_fetch"), 1)
            ]
        );
        assert_eq!(summary.counts[&("libssl", "SSL_new")], [2, 1, 0]);
        assert_eq!(
            summary.unknown.keys().collect::<Vec<_>>(),
            [&("libssl", "SSL_free", "OPENSSL_3.6.0")]
        );
        let needed = needed_ranks(&scanned, &summary);
        assert_eq!(
            needed,
            [(0, Some(1)), (0, Some(2)), (1, Some(1)), (2, None)]
        );

        let listings: Vec<Listing> = (0..3)
            .map(|_| Listing {
                openssl: "3.5.5".to_owned(),
                packages: Vec::new(),
            })
            .collect();
        let report = render(&listings, &scanned, &exports, "2026-10-07").unwrap();
        assert!(report.contains("| 1 | `SSL_new` | libssl | 2 | 1 | 0 | 3 |"));
        assert!(report.contains("| `SSL_free@OPENSSL_3.6.0` | libssl | Fedora c |"));
        assert!(report.contains("| Fedora `broken` | bad archive |"));
        assert!(report.contains("| 2 (all imported) | 2 of 2 | 1 of 1 | 0 of 1 | 3 of 4 |"));
        assert!(report.contains("2 exports that no scanned package imports"));
    }
}
