//! Per-distribution export profiles (`cargo xtask dist --profile <name>`): what a
//! distribution's libcrypto exports beyond upstream's default build, so that binaries built on
//! that distribution load on rustyssl's. Each profile's extra functions come from the `.num`
//! files by feature; only the decision (which features, which extra version nodes) is written
//! here. The default build has no profile and stays upstream's.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::util::Result;

/// A distribution's ABI extras.
pub struct Profile {
    /// The name `--profile` takes, and the suffix of its export lists.
    pub name: &'static str,
    /// The Cargo feature of `rustyssl-libcrypto` that implements the extras.
    pub feature: &'static str,
    /// `.num` features upstream's default build disables that the distribution enables: their
    /// functions are exported at the version the `.num` file gives them.
    pub features: &'static [&'static str],
    /// Functions the distribution also exports at an older version node, as a non-default
    /// version (`name@node`) beside upstream's default.
    pub aliases: &'static [(&'static str, &'static str)],
}

/// Fedora (the user's decision in Phase 12.3): its libcrypto is built with `enable-md2` and
/// `enable-sctp`, and patches `EVP_MD_CTX_dup` and `EVP_CIPHER_CTX_dup` in at
/// `OPENSSL_3.1.0`, which Fedora's binaries bind to (docs/symbol-usage.md, the Fedora 44 scan:
/// ipmitool, perl-Net-SSLeay, qca, openssl, dpdk).
pub const FEDORA: Profile = Profile {
    name: "fedora",
    feature: "fedora",
    features: &["MD2", "SCTP"],
    aliases: &[
        ("EVP_MD_CTX_dup", "OPENSSL_3.1.0"),
        ("EVP_CIPHER_CTX_dup", "OPENSSL_3.1.0"),
    ],
};

pub const PROFILES: &[&Profile] = &[&FEDORA];

/// Finds a profile by name.
pub fn find(name: &str) -> Result<&'static Profile> {
    PROFILES
        .iter()
        .copied()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
            format!("unknown profile `{name}` (known: {})", names.join(", ")).into()
        })
}

/// The functions of `num` (a `.num` file's text) that need one of `features`, by version node
/// (`OPENSSL_3.0.0`), where every other feature they need is one the default build has: a
/// deprecation, or another of `features`, or `DGRAM`/`SOCK`.
pub fn extra_functions(num: &str, features: &[&str]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut nodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in num.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [name, _, version, info, ..] = fields.as_slice() else {
            return Err(format!("bad .num line: {line}").into());
        };
        // `EXIST::FUNCTION:<features>`.
        let Some(features_needed) = info.strip_prefix("EXIST::FUNCTION:") else {
            continue;
        };
        let needs: Vec<&str> = features_needed
            .split(',')
            .filter(|f| !f.is_empty())
            .collect();
        let wanted = needs.iter().any(|f| features.contains(f));
        let available = needs.iter().all(|f| {
            features.contains(f) || f.starts_with("DEPRECATEDIN_") || matches!(*f, "DGRAM" | "SOCK")
        });
        if wanted && available {
            let node = format!("OPENSSL_{}", version.replace('_', "."));
            nodes.entry(node).or_default().push((*name).to_owned());
        }
    }
    if nodes.is_empty() {
        return Err(format!("no functions need {features:?}").into());
    }
    Ok(nodes)
}

/// Reads `libcrypto.num` under `abi` and returns the profile's extra functions.
pub fn libcrypto_extras(abi: &Path, profile: &Profile) -> Result<BTreeMap<String, Vec<String>>> {
    let num = fs::read_to_string(abi.join("util/libcrypto.num"))?;
    extra_functions(&num, profile.features)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_features_functions_by_version() {
        let num = "EVP_md2 259 3_0_0 EXIST::FUNCTION:MD2\n\
                   MD2_Init 3244 3_0_0 EXIST::FUNCTION:DEPRECATEDIN_3_0,MD2\n\
                   BIO_new_dgram_sctp 332 3_0_0 EXIST::FUNCTION:DGRAM,SCTP\n\
                   EVP_md4 1 3_0_0 EXIST::FUNCTION:MD4\n\
                   SSL_x 2 3_2_0 EXIST::FUNCTION:SCTP,SRP\n\
                   EVP_md5 3 3_0_0 EXIST::FUNCTION:\n";
        let nodes = extra_functions(num, &["MD2", "SCTP"]).unwrap();
        assert_eq!(
            nodes.get("OPENSSL_3.0.0").unwrap(),
            &["EVP_md2", "MD2_Init", "BIO_new_dgram_sctp"]
        );
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn fedora_has_md2_and_sctp() {
        let abi = crate::util::workspace_root().join(format!(
            "abi/openssl-{}",
            crate::targets::OPENSSL_SERIES
        ));
        let nodes = libcrypto_extras(&abi, &FEDORA).unwrap();
        let names: Vec<&str> = nodes.values().flatten().map(String::as_str).collect();
        for name in ["EVP_md2", "MD2", "MD2_Init", "MD2_options", "BIO_new_dgram_sctp", "BIO_dgram_is_sctp"] {
            assert!(names.contains(&name), "{name}");
        }
        assert_eq!(names.len(), 12, "{names:?}");
    }
}
