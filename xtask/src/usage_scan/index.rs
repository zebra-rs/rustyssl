//! Reads the package indexes: which packages depend on OpenSSL, and where each one is. A Debian
//! or Ubuntu `Packages` file lists each package's `Depends`; Fedora's `primary.xml` lists the
//! sonames each package requires.
//!
//! Indexes are untrusted input too. A package's path is used to build a download URL, so it
//! must be a plain relative path, and its checksum must look like one.

use crate::util::Result;

/// A package to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    /// The path relative to the repository root (`pool/main/c/curl/curl_8.14.1_amd64.deb`).
    pub path: String,
    /// Lowercase hex SHA-256 of the package file.
    pub sha256: String,
}

/// The packages in a Debian `Packages` index that depend directly on one of `wanted`.
pub fn debian(index: &str, wanted: &[&str]) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    for stanza in index.split("\n\n") {
        let mut name = None;
        let mut path = None;
        let mut sha256 = None;
        let mut depends = String::new();
        let mut in_depends = false;
        for line in stanza.lines() {
            // A line starting with whitespace continues the previous field.
            if line.starts_with([' ', '\t']) {
                if in_depends {
                    depends.push_str(line);
                }
                continue;
            }
            let (key, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.trim();
            in_depends = matches!(key, "Depends" | "Pre-Depends");
            match key {
                "Package" => name = Some(value),
                "Filename" => path = Some(value),
                "SHA256" => sha256 = Some(value),
                _ if in_depends => {
                    depends.push(',');
                    depends.push_str(value);
                }
                _ => {}
            }
        }
        let Some(name) = name else {
            continue;
        };
        if depends_on(&depends, wanted) {
            packages.push(package(
                name,
                path.ok_or_else(|| format!("{name}: no Filename"))?,
                sha256.ok_or_else(|| format!("{name}: no SHA256"))?,
            )?);
        }
    }
    Ok(packages)
}

/// The version of `package` in a Debian `Packages` index.
pub fn debian_version(index: &str, package: &str) -> Option<String> {
    index.split("\n\n").find_map(|stanza| {
        let mut lines = stanza.lines();
        if lines.next()? != format!("Package: {package}") {
            return None;
        }
        lines.find_map(|line| line.strip_prefix("Version: ").map(str::to_owned))
    })
}

/// Whether a Debian dependency field names one of `wanted`, in any alternative and with any
/// version or architecture qualifier.
fn depends_on(field: &str, wanted: &[&str]) -> bool {
    field.split([',', '|']).any(|alternative| {
        let name = alternative
            .trim()
            .split([' ', '(', ':'])
            .next()
            .unwrap_or_default();
        wanted.contains(&name)
    })
}

/// The location and SHA-256 of the `primary` metadata in Fedora's `repomd.xml`.
pub fn fedora_primary(repomd: &str) -> Result<(String, String)> {
    let data = repomd
        .split("<data type=\"primary\">")
        .nth(1)
        .and_then(|rest| rest.split("</data>").next())
        .ok_or("repomd.xml lists no primary data")?;
    let path = between(data, "<location href=\"", "\"").ok_or("no primary location")?;
    let sha256 =
        between(data, "<checksum type=\"sha256\">", "</checksum>").ok_or("no primary checksum")?;
    let checked = package("primary", path, sha256)?;
    Ok((checked.path, checked.sha256))
}

/// The `arch` packages in Fedora's `primary.xml` that require a soname starting with one of
/// `wanted` (`libssl.so.3` matches `libssl.so.3()(64bit)` and `libssl.so.3(OPENSSL_3.0.0)`).
pub fn fedora(primary: &str, arch: &str, wanted: &[&str]) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    for chunk in primary.split("<package type=\"rpm\">").skip(1) {
        let body = chunk.split("</package>").next().unwrap_or_default();
        if between(body, "<arch>", "</arch>") != Some(arch) {
            continue;
        }
        let requires = between(body, "<rpm:requires>", "</rpm:requires>").unwrap_or_default();
        let uses = requires
            .split("<rpm:entry name=\"")
            .skip(1)
            .filter_map(|entry| entry.split('"').next())
            .any(|soname| {
                wanted.iter().any(|w| {
                    soname
                        .strip_prefix(w)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('('))
                })
            });
        if !uses {
            continue;
        }
        let name = between(body, "<name>", "</name>").ok_or("package without a name")?;
        packages.push(package(
            name,
            between(body, "<location href=\"", "\"")
                .ok_or_else(|| format!("{name}: no location"))?,
            between(
                body,
                "<checksum type=\"sha256\" pkgid=\"YES\">",
                "</checksum>",
            )
            .ok_or_else(|| format!("{name}: no sha256 checksum"))?,
        )?);
    }
    Ok(packages)
}

/// The version-release of the `arch` package `name` in Fedora's `primary.xml`.
pub fn fedora_version(primary: &str, name: &str, arch: &str) -> Option<String> {
    primary.split("<package type=\"rpm\">").find_map(|body| {
        if between(body, "<name>", "</name>")? != name
            || between(body, "<arch>", "</arch>")? != arch
        {
            return None;
        }
        let version = between(body, "<version ", "/>")?;
        let ver = between(version, "ver=\"", "\"")?;
        let rel = between(version, "rel=\"", "\"")?;
        Some(format!("{ver}-{rel}"))
    })
}

/// The text between the first `start` and the next `end`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = text.split_once(start)?.1;
    Some(rest.split_once(end)?.0)
}

/// Checks a package's fields before they're used in a URL or a cache file name.
fn package(name: &str, path: &str, sha256: &str) -> Result<Package> {
    let safe_path = !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+~^-/".contains(&b));
    if !safe_path {
        return Err(format!("{name}: unsafe package path {path:?}").into());
    }
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{name}: bad SHA-256 {sha256:?}").into());
    }
    Ok(Package {
        name: name.to_owned(),
        path: path.to_owned(),
        sha256: sha256.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn debian_dependents() {
        let index = format!(
            "Package: curl\nVersion: 8\nDepends: libc6 (>= 2.34), libcurl4t64 (= 8),\n \
             libssl3t64 (>= 3.0.0)\nFilename: pool/main/c/curl/curl_8_amd64.deb\nSHA256: {HASH}\n\n\
             Package: wget\nPre-Depends: libssl3t64:amd64 (>= 3)\nFilename: pool/w.deb\nSHA256: {HASH}\n\n\
             Package: alt\nDepends: libgnutls30t64 | libssl3\nFilename: pool/a.deb\nSHA256: {HASH}\n\n\
             Package: lookalike\nDepends: libssl3t64-dev\nFilename: pool/l.deb\nSHA256: {HASH}\n\n\
             Package: other\nDepends: libc6\nFilename: pool/o.deb\nSHA256: {HASH}\n"
        );
        assert_eq!(debian_version(&index, "curl").as_deref(), Some("8"));
        assert_eq!(debian_version(&index, "libssl3t64"), None);
        let found = debian(&index, &["libssl3t64", "libssl3"]).unwrap();
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        // curl's dependency is on a continuation line.
        assert_eq!(names, ["curl", "wget", "alt"]);
        assert_eq!(found[1].path, "pool/w.deb");
    }

    #[test]
    fn dependency_fields() {
        let wanted = ["libssl3t64"];
        assert!(depends_on("libc6, libssl3t64 (>= 3.0.0)", &wanted));
        assert!(depends_on("libgnutls30 | libssl3t64:amd64", &wanted));
        assert!(!depends_on("libssl3t64-dev, libssl-dev", &wanted));
        assert!(!depends_on("", &wanted));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        let index = |path: &str| {
            format!("Package: x\nDepends: libssl3t64\nFilename: {path}\nSHA256: {HASH}\n")
        };
        assert!(debian(&index("pool/x.deb"), &["libssl3t64"]).is_ok());
        // Fedora's snapshot versions use a caret.
        assert!(
            debian(
                &index("Packages/d/d-0^20230708git4aea40b-10.fc44.x86_64.rpm"),
                &["libssl3t64"]
            )
            .is_ok()
        );
        for bad in [
            "../x.deb",
            "/etc/passwd",
            "pool/../../x",
            "pool//x",
            "pool/x y.deb",
            "pool/x?y",
        ] {
            assert!(debian(&index(bad), &["libssl3t64"]).is_err(), "{bad}");
        }
        let short = "Package: x\nDepends: libssl3t64\nFilename: pool/x.deb\nSHA256: abc\n";
        assert!(debian(short, &["libssl3t64"]).is_err());
    }

    #[test]
    fn fedora_metadata() {
        let repomd = format!(
            "<repomd><data type=\"other\"><location href=\"repodata/o.xml.zst\"/></data>\
             <data type=\"primary\"><checksum type=\"sha256\">{HASH}</checksum>\
             <location href=\"repodata/p-primary.xml.zst\"/></data></repomd>"
        );
        assert_eq!(
            fedora_primary(&repomd).unwrap(),
            ("repodata/p-primary.xml.zst".to_owned(), HASH.to_owned())
        );

        let package = |name: &str, arch: &str, requires: &str| {
            format!(
                "<package type=\"rpm\">\n  <name>{name}</name>\n  <arch>{arch}</arch>\n  \
                 <checksum type=\"sha256\" pkgid=\"YES\">{HASH}</checksum>\n  \
                 <location href=\"Packages/{name}.rpm\"/>\n  <format>\n    <rpm:requires>\n{requires}\
                 \n    </rpm:requires>\n  </format>\n</package>\n"
            )
        };
        let primary = [
            package(
                "curl",
                "x86_64",
                "<rpm:entry name=\"libssl.so.3()(64bit)\"/>",
            ),
            package(
                "tool",
                "x86_64",
                "<rpm:entry name=\"libcrypto.so.3(OPENSSL_3.0.0)(64bit)\"/>",
            ),
            package("curl", "i686", "<rpm:entry name=\"libssl.so.3\"/>"),
            package(
                "other",
                "x86_64",
                "<rpm:entry name=\"libssl.so.30()(64bit)\"/>",
            ),
            package(
                "plain",
                "x86_64",
                "<rpm:entry name=\"libc.so.6()(64bit)\"/>",
            ),
        ]
        .concat();
        let versioned = primary.replacen(
            "<arch>x86_64</arch>",
            "<arch>x86_64</arch>\n  <version epoch=\"1\" ver=\"3.5.5\" rel=\"1.fc44\"/>",
            1,
        );
        assert_eq!(
            fedora_version(&versioned, "curl", "x86_64").as_deref(),
            Some("3.5.5-1.fc44")
        );
        assert_eq!(fedora_version(&versioned, "curl", "i686"), None);
        let found = fedora(&primary, "x86_64", &["libssl.so.3", "libcrypto.so.3"]).unwrap();
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["curl", "tool"]);
        assert_eq!(found[0].path, "Packages/curl.rpm");
    }
}
