//! `cargo xtask test-wycheproof [file...]`: Wycheproof's test vectors (TEST_PLAN.md, layer L2)
//! on the reference and on rustyssl.
//!
//! The files listed in `tests/wycheproof/files.txt` are fetched from the Wycheproof repository
//! at the commit pinned there, into `target/testdata/`, and checked against their SHA-256
//! checksums. Each test becomes a line for `tests/wycheproof/runner.c`, which computes what
//! the library gives (ciphertexts and plaintexts, tags, derived keys, or failures); each file
//! runs once on the reference libraries and once on rustyssl's. A test passes when:
//!
//! - rustyssl prints the same as the reference, failures' error codes included; and
//! - the result agrees with Wycheproof's verdict: a valid test's outputs are the expected
//!   ones, and an invalid test's decryption or verification fails. Where the reference itself
//!   disagrees, the test must be listed in `tests/wycheproof/reference.txt` with the reason,
//!   so every departure is accounted for (and a listed test that agrees fails, as stale).
//!
//! Tests of algorithms the reference doesn't offer (AES-192-XTS) are skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json::{self, Value};
use crate::test_c::{compile, execute_with_input, prepare};
use crate::util::{Result, fresh_dir, run_output, sha256_file, target_dir, workspace_root};

const REPOSITORY: &str = "https://raw.githubusercontent.com/C2SP/wycheproof";

/// What a file's tests exercise, and how its tests become runner commands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// AEAD with a nonce (`AeadTest`).
    Aead,
    /// AES-SIV as a nonce-based AEAD (RFC 5297): the AAD, then the nonce, as S2V components.
    AeadSiv,
    /// Deterministic AES-SIV (`DaeadTest`): one AAD component, the tag ahead of the ciphertext.
    Daead,
    /// A block cipher with padding (`IndCpaTest`).
    Cipher,
    /// XTS: the tweak zero-padded to 16 octets.
    Xts,
    /// Key wrap (`KeywrapTest`).
    Wrap,
    /// A MAC (`MacTest`), its tag possibly truncated.
    Mac,
    /// A MAC with an IV (`MacWithIvTest`, GMAC).
    MacIv,
    Hkdf,
    Pbkdf2,
    /// PBES2: PBKDF2, then AES-CBC with padding (`PbeTest`).
    Pbes2,
}

/// Each file's kind and its algorithm, as the runner names it: `{k}` stands for the key's
/// bits, `{h}` for half of them, and `{t}` for the tag's octets. For MACs, the MAC's name and
/// its parameters; for PBES2, the digest and the cipher.
#[rustfmt::skip]
const FILES: &[(&str, Kind, &str)] = &[
    ("aead_aes_siv_cmac", Kind::AeadSiv, "AES-{h}-SIV"),
    ("aes_cbc_pkcs5", Kind::Cipher, "AES-{k}-CBC"),
    ("aes_ccm", Kind::Aead, "AES-{k}-CCM"),
    ("aes_cmac", Kind::Mac, "CMAC cipher=AES-{k}-CBC"),
    ("aes_gcm", Kind::Aead, "AES-{k}-GCM"),
    ("aes_gcm_siv", Kind::Aead, "AES-{k}-GCM-SIV"),
    ("aes_gmac", Kind::MacIv, "GMAC cipher=AES-{k}-GCM"),
    ("aes_kwp", Kind::Wrap, "AES-{k}-WRAP-PAD"),
    ("aes_siv_cmac", Kind::Daead, "AES-{h}-SIV"),
    ("aes_wrap", Kind::Wrap, "AES-{k}-WRAP"),
    ("aes_xts", Kind::Xts, "AES-{h}-XTS"),
    ("aria_cbc_pkcs5", Kind::Cipher, "ARIA-{k}-CBC"),
    ("aria_ccm", Kind::Aead, "ARIA-{k}-CCM"),
    ("aria_cmac", Kind::Mac, "CMAC cipher=ARIA-{k}-CBC"),
    ("aria_gcm", Kind::Aead, "ARIA-{k}-GCM"),
    ("camellia_cbc_pkcs5", Kind::Cipher, "CAMELLIA-{k}-CBC"),
    ("camellia_cmac", Kind::Mac, "CMAC cipher=CAMELLIA-{k}-CBC"),
    ("chacha20_poly1305", Kind::Aead, "ChaCha20-Poly1305"),
    ("hkdf_sha1", Kind::Hkdf, "SHA1"),
    ("hkdf_sha256", Kind::Hkdf, "SHA2-256"),
    ("hkdf_sha384", Kind::Hkdf, "SHA2-384"),
    ("hkdf_sha512", Kind::Hkdf, "SHA2-512"),
    ("hmac_sha1", Kind::Mac, "HMAC digest=SHA1"),
    ("hmac_sha224", Kind::Mac, "HMAC digest=SHA2-224"),
    ("hmac_sha256", Kind::Mac, "HMAC digest=SHA2-256"),
    ("hmac_sha384", Kind::Mac, "HMAC digest=SHA2-384"),
    ("hmac_sha512", Kind::Mac, "HMAC digest=SHA2-512"),
    ("hmac_sha3_224", Kind::Mac, "HMAC digest=SHA3-224"),
    ("hmac_sha3_256", Kind::Mac, "HMAC digest=SHA3-256"),
    ("hmac_sha3_384", Kind::Mac, "HMAC digest=SHA3-384"),
    ("hmac_sha3_512", Kind::Mac, "HMAC digest=SHA3-512"),
    ("hmac_sha512_224", Kind::Mac, "HMAC digest=SHA2-512/224"),
    ("hmac_sha512_256", Kind::Mac, "HMAC digest=SHA2-512/256"),
    ("hmac_sm3", Kind::Mac, "HMAC digest=SM3"),
    ("kmac128_no_customization", Kind::Mac, "KMAC-128 size={t}"),
    ("kmac256_no_customization", Kind::Mac, "KMAC-256 size={t}"),
    ("pbes2_hmacsha1_aes_128", Kind::Pbes2, "SHA1 AES-128-CBC"),
    ("pbes2_hmacsha1_aes_192", Kind::Pbes2, "SHA1 AES-192-CBC"),
    ("pbes2_hmacsha1_aes_256", Kind::Pbes2, "SHA1 AES-256-CBC"),
    ("pbes2_hmacsha224_aes_128", Kind::Pbes2, "SHA2-224 AES-128-CBC"),
    ("pbes2_hmacsha224_aes_192", Kind::Pbes2, "SHA2-224 AES-192-CBC"),
    ("pbes2_hmacsha224_aes_256", Kind::Pbes2, "SHA2-224 AES-256-CBC"),
    ("pbes2_hmacsha256_aes_128", Kind::Pbes2, "SHA2-256 AES-128-CBC"),
    ("pbes2_hmacsha256_aes_192", Kind::Pbes2, "SHA2-256 AES-192-CBC"),
    ("pbes2_hmacsha256_aes_256", Kind::Pbes2, "SHA2-256 AES-256-CBC"),
    ("pbes2_hmacsha384_aes_128", Kind::Pbes2, "SHA2-384 AES-128-CBC"),
    ("pbes2_hmacsha384_aes_192", Kind::Pbes2, "SHA2-384 AES-192-CBC"),
    ("pbes2_hmacsha384_aes_256", Kind::Pbes2, "SHA2-384 AES-256-CBC"),
    ("pbes2_hmacsha512_aes_128", Kind::Pbes2, "SHA2-512 AES-128-CBC"),
    ("pbes2_hmacsha512_aes_192", Kind::Pbes2, "SHA2-512 AES-192-CBC"),
    ("pbes2_hmacsha512_aes_256", Kind::Pbes2, "SHA2-512 AES-256-CBC"),
    ("pbkdf2_hmacsha1", Kind::Pbkdf2, "SHA1"),
    ("pbkdf2_hmacsha224", Kind::Pbkdf2, "SHA2-224"),
    ("pbkdf2_hmacsha256", Kind::Pbkdf2, "SHA2-256"),
    ("pbkdf2_hmacsha384", Kind::Pbkdf2, "SHA2-384"),
    ("pbkdf2_hmacsha512", Kind::Pbkdf2, "SHA2-512"),
    ("siphash_1_3", Kind::Mac, "SIPHASH size=8,c-rounds=1,d-rounds=3"),
    ("siphash_2_4", Kind::Mac, "SIPHASH size=8,c-rounds=2,d-rounds=4"),
    ("siphash_4_8", Kind::Mac, "SIPHASH size=8,c-rounds=4,d-rounds=8"),
    ("siphashx_2_4", Kind::Mac, "SIPHASH size=16,c-rounds=2,d-rounds=4"),
    ("siphashx_4_8", Kind::Mac, "SIPHASH size=16,c-rounds=4,d-rounds=8"),
    ("sm4_ccm", Kind::Aead, "SM4-CCM"),
    ("sm4_gcm", Kind::Aead, "SM4-GCM"),
];

/// Algorithms Wycheproof tests that the reference doesn't offer: their tests are skipped.
const UNOFFERED: &[&str] = &["AES-192-XTS"];

/// One test, as run and judged.
struct Case {
    tc_id: u64,
    kind: Kind,
    result: String,
    /// The runner's command line, without the leading id.
    command: String,
    /// What a valid test must print: each of the runner's fields, in order.
    expected: Vec<String>,
    /// For a MAC: the expected tag, which the computed one must start with.
    tag: Option<String>,
}

/// A hex field as the runner takes it: `_` for empty.
fn field(hex: &str) -> String {
    if hex.is_empty() {
        "_".to_owned()
    } else {
        hex.to_ascii_lowercase()
    }
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no string `{key}`").into())
}

fn number(v: &Value, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("no number `{key}`").into())
}

/// The algorithm template filled in for a group.
fn fill(template: &str, group: &Value) -> String {
    let bits = group.get("keySize").and_then(Value::as_u64).unwrap_or(0);
    let tag = group.get("tagSize").and_then(Value::as_u64).unwrap_or(0) / 8;
    template
        .replace("{k}", &bits.to_string())
        .replace("{h}", &(bits / 2).to_string())
        .replace("{t}", &tag.to_string())
}

/// The cases of one file.
fn cases(kind: Kind, template: &str, doc: &Value) -> Result<(Vec<Case>, usize)> {
    let mut cases = Vec::new();
    let mut skipped = 0;
    for group in doc
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("no testGroups")?
    {
        let algorithm = fill(template, group);
        let tests = group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("no tests")?;
        if UNOFFERED.contains(&algorithm.as_str()) {
            skipped += tests.len();
            continue;
        }
        let taglen = group.get("tagSize").and_then(Value::as_u64).unwrap_or(0) / 8;
        for t in tests {
            let s = |key: &str| text(t, key).map(field);
            let (command, expected, tag) = match kind {
                Kind::Aead | Kind::AeadSiv => {
                    let (iv, aads) = if kind == Kind::Aead {
                        let aad = text(t, "aad")?;
                        (
                            s("iv")?,
                            if aad.is_empty() {
                                "-".to_owned()
                            } else {
                                field(aad)
                            },
                        )
                    } else {
                        ("-".to_owned(), format!("{},{}", s("aad")?, s("iv")?))
                    };
                    (
                        format!(
                            "aead {algorithm} {taglen} {} {iv} {aads} {} {} {}",
                            s("key")?,
                            s("msg")?,
                            s("ct")?,
                            s("tag")?
                        ),
                        vec![
                            format!("E:{}/{}", s("ct")?, s("tag")?),
                            format!("D:{}", s("msg")?),
                        ],
                        None,
                    )
                }
                Kind::Daead => {
                    let ct = text(t, "ct")?.to_ascii_lowercase();
                    let (tag, body) = ct.split_at(ct.len().min(32));
                    (
                        format!(
                            "aead {algorithm} 16 {} - {} {} {} {}",
                            s("key")?,
                            s("aad")?,
                            s("msg")?,
                            field(body),
                            field(tag)
                        ),
                        vec![
                            format!("E:{}/{}", field(body), field(tag)),
                            format!("D:{}", s("msg")?),
                        ],
                        None,
                    )
                }
                Kind::Cipher | Kind::Xts | Kind::Wrap => {
                    let iv = match kind {
                        Kind::Wrap => "-".to_owned(),
                        Kind::Xts => format!("{:0<32}", text(t, "iv")?.to_ascii_lowercase()),
                        _ => s("iv")?,
                    };
                    (
                        format!(
                            "cipher {algorithm} {} {iv} {} {}",
                            s("key")?,
                            s("msg")?,
                            s("ct")?
                        ),
                        vec![format!("E:{}", s("ct")?), format!("D:{}", s("msg")?)],
                        None,
                    )
                }
                Kind::Mac | Kind::MacIv => {
                    let (name, params) = algorithm.split_once(' ').unwrap_or((&algorithm, "-"));
                    let params = if kind == Kind::MacIv {
                        format!("{params},iv={}", s("iv")?)
                    } else {
                        params.to_owned()
                    };
                    (
                        format!("mac {name} {params} {} {}", s("key")?, s("msg")?),
                        Vec::new(),
                        Some(text(t, "tag")?.to_ascii_lowercase()),
                    )
                }
                Kind::Hkdf => (
                    format!(
                        "hkdf {algorithm} {} {} {} {}",
                        s("ikm")?,
                        s("salt")?,
                        s("info")?,
                        number(t, "size")?
                    ),
                    vec![format!("K:{}", s("okm")?)],
                    None,
                ),
                Kind::Pbkdf2 => (
                    format!(
                        "pbkdf2 {algorithm} {} {} {} {}",
                        s("password")?,
                        s("salt")?,
                        number(t, "iterationCount")?,
                        number(t, "dkLen")?
                    ),
                    vec![format!("K:{}", s("dk")?)],
                    None,
                ),
                Kind::Pbes2 => (
                    format!(
                        "pbes2 {algorithm} {} {} {} {} {} {}",
                        s("password")?,
                        s("salt")?,
                        number(t, "iterationCount")?,
                        s("iv")?,
                        s("msg")?,
                        s("ct")?
                    ),
                    vec![format!("E:{}", s("ct")?), format!("D:{}", s("msg")?)],
                    None,
                ),
            };
            cases.push(Case {
                tc_id: number(t, "tcId")?,
                kind,
                result: text(t, "result")?.to_owned(),
                command,
                expected,
                tag,
            });
        }
    }
    Ok((cases, skipped))
}

/// Whether the runner's fields for `case` agree with Wycheproof's verdict.
fn agrees(case: &Case, fields: &[&str]) -> bool {
    let failed = |prefix: &str| {
        fields
            .iter()
            .find(|f| f.starts_with(prefix))
            .is_none_or(|f| f.strip_prefix(prefix).is_none_or(|v| v.starts_with("fail")))
    };
    match case.result.as_str() {
        "valid" => match &case.tag {
            Some(tag) => fields
                .first()
                .and_then(|f| f.strip_prefix("T:"))
                .is_some_and(|t| !t.starts_with("fail") && t.starts_with(tag.as_str())),
            None => fields
                .iter()
                .copied()
                .eq(case.expected.iter().map(String::as_str)),
        },
        "invalid" => match case.kind {
            Kind::Mac | Kind::MacIv => {
                let tag = case.tag.as_deref().unwrap_or_default();
                fields
                    .first()
                    .and_then(|f| f.strip_prefix("T:"))
                    .is_none_or(|t| t.starts_with("fail") || !t.starts_with(tag))
            }
            Kind::Hkdf | Kind::Pbkdf2 => failed("K:"),
            // An invalid key to wrap comes with no ciphertext: wrapping it must fail.
            Kind::Wrap if case.expected.first().is_some_and(|e| e == "E:_") => failed("E:"),
            _ => failed("D:"),
        },
        _ => true,
    }
}

/// `tests/wycheproof/reference.txt`: (file, tcId) of the tests where the reference disagrees
/// with Wycheproof. Lines are `<file> <tcId>[,<tcId>...] <reason>`.
fn reference_departures(root: &Path) -> Result<BTreeSet<(String, u64)>> {
    let mut set = BTreeSet::new();
    let text = fs::read_to_string(root.join("tests/wycheproof/reference.txt"))?;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(file), Some(ids), Some(_reason)) = (words.next(), words.next(), words.next())
        else {
            return Err(format!("reference.txt: `{line}` needs a file, ids, and a reason").into());
        };
        for id in ids.split(',') {
            let id: u64 = id
                .parse()
                .map_err(|_| format!("reference.txt: bad test id `{id}`"))?;
            set.insert((file.to_owned(), id));
        }
    }
    Ok(set)
}

/// The pinned commit and each file's checksum, from `tests/wycheproof/files.txt`.
fn manifest(root: &Path) -> Result<(String, BTreeMap<String, String>)> {
    let text = fs::read_to_string(root.join("tests/wycheproof/files.txt"))?;
    let mut commit = None;
    let mut files = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once(' ') {
            Some(("commit", c)) => commit = Some(c.to_owned()),
            Some((sum, name)) => {
                files.insert(name.to_owned(), sum.to_owned());
            }
            None => return Err(format!("files.txt: bad line `{line}`").into()),
        }
    }
    Ok((commit.ok_or("files.txt has no commit")?, files))
}

/// The file `name` of the pinned commit, fetched unless a verified copy is there.
fn fetch(dir: &Path, commit: &str, name: &str, sum: &str) -> Result<PathBuf> {
    let path = dir.join(format!("{name}_test.json"));
    if path.exists() && sha256_file(&path)? == sum {
        return Ok(path);
    }
    let url = format!("{REPOSITORY}/{commit}/testvectors_v1/{name}_test.json");
    let partial = dir.join(format!("{name}_test.json.part"));
    run_output(
        Command::new("curl")
            .args(["-sSfL", "--retry", "3", "-o"])
            .arg(&partial)
            .arg(&url),
    )?;
    let got = sha256_file(&partial)?;
    if got != sum {
        fs::remove_file(&partial)?;
        return Err(format!("{url}: SHA-256 {got}, expected {sum}").into());
    }
    fs::rename(&partial, &path)?;
    Ok(path)
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let (commit, sums) = manifest(&root)?;
    let selected: Vec<&(&str, Kind, &str)> = FILES
        .iter()
        .filter(|(name, _, _)| args.is_empty() || args.iter().any(|a| a == name))
        .collect();
    if selected.is_empty() {
        return Err("no Wycheproof files selected".into());
    }
    for name in sums.keys() {
        if !FILES.iter().any(|(n, _, _)| n == name) {
            return Err(format!("files.txt lists {name}, which the runner's table hasn't").into());
        }
    }
    let data = target_dir(&root).join(format!("testdata/wycheproof-{commit}"));
    fs::create_dir_all(&data)?;
    let departures = reference_departures(&root)?;

    let (reference, dist) = prepare(&root)?;
    let work = target_dir(&root).join("xtask/test-wycheproof");
    fresh_dir(&work)?;
    let runner = work.join("runner");
    compile(
        &root.join("tests/wycheproof/runner.c"),
        &runner,
        &dist,
        &reference,
    )?;

    // Every problem, where the summary shows a few per file.
    let report_path = work.join("report.txt");
    let mut report = String::new();
    let mut failures = 0;
    let (mut total, mut skipped_total, mut departed_total) = (0, 0, 0);
    for (name, kind, template) in selected {
        let sum = sums
            .get(*name)
            .ok_or_else(|| format!("files.txt has no checksum for {name}"))?;
        let path = fetch(&data, &commit, name, sum)?;
        let doc = json::parse(&fs::read_to_string(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let (cases, skipped) = cases(*kind, template, &doc).map_err(|e| format!("{name}: {e}"))?;
        let input = work.join(format!("{name}.in"));
        let lines: Vec<String> = cases
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{i} {}\n", c.command))
            .collect();
        fs::write(&input, lines.concat())?;

        let theirs = execute_with_input(&runner, &reference.join("lib"), &work, Some(&input))?;
        let ours = execute_with_input(&runner, &dist.join("lib"), &work, Some(&input))?;
        let mut problems = Vec::new();
        if !theirs.success {
            problems.push(format!(
                "the reference run exits with {}: {}",
                theirs.status,
                theirs.stderr.trim()
            ));
        }
        if !ours.success {
            problems.push(format!(
                "the rustyssl run exits with {}: {}",
                ours.status,
                ours.stderr.trim()
            ));
        }
        let (their_lines, our_lines): (Vec<&str>, Vec<&str>) = (
            theirs.stdout.lines().collect(),
            ours.stdout.lines().collect(),
        );
        if problems.is_empty()
            && (their_lines.len() != cases.len() || our_lines.len() != cases.len())
        {
            problems.push(format!(
                "{} tests, but {} lines from the reference and {} from rustyssl",
                cases.len(),
                their_lines.len(),
                our_lines.len()
            ));
        }
        let mut departed = 0;
        if problems.is_empty() {
            for ((case, theirs), ours) in cases.iter().zip(&their_lines).zip(&our_lines) {
                let fields: Vec<&str> = ours.split(' ').skip(1).collect();
                let listed = departures.contains(&((*name).to_owned(), case.tc_id));
                if theirs != ours {
                    problems.push(format!(
                        "tcId {}: differs from the reference\n    reference: {theirs}\n    rustyssl:  {ours}",
                        case.tc_id
                    ));
                } else if agrees(case, &fields) {
                    if listed {
                        problems.push(format!(
                            "tcId {}: listed in reference.txt, but agrees with Wycheproof",
                            case.tc_id
                        ));
                    }
                } else if listed {
                    departed += 1;
                } else {
                    problems.push(format!(
                        "tcId {} ({}): the reference and rustyssl disagree with Wycheproof: {ours}",
                        case.tc_id, case.result
                    ));
                }
            }
        }
        total += cases.len();
        skipped_total += skipped;
        departed_total += departed;
        if problems.is_empty() {
            let mut notes = Vec::new();
            if departed > 0 {
                notes.push(format!("{departed} where the reference departs"));
            }
            if skipped > 0 {
                notes.push(format!("{skipped} skipped"));
            }
            let notes = if notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", notes.join(", "))
            };
            println!("PASS {name}: {} tests{notes}", cases.len());
        } else {
            failures += 1;
            for p in &problems {
                report.push_str(&format!("{name}: {p}\n"));
            }
            println!("FAIL {name}: {} problem(s)", problems.len());
            for p in problems.iter().take(5) {
                println!("  {p}");
            }
        }
    }
    fs::write(&report_path, report)?;
    if failures > 0 {
        return Err(format!(
            "{failures} file(s) failed (every problem: {})",
            report_path.display()
        )
        .into());
    }
    println!(
        "{total} Wycheproof tests agree on rustyssl and the reference ({departed_total} where the \
         reference departs from Wycheproof, listed; {skipped_total} skipped)"
    );
    Ok(())
}
