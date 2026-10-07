//! Which functions an ELF file imports from given libraries: its undefined dynamic symbols
//! whose GNU symbol version (`.gnu.version`) names a version that `.gnu.version_r` says comes
//! from one of those files (`SSL_new@OPENSSL_3.0.0` from `libssl.so.3`).
//!
//! Files come from downloaded packages, so they're untrusted input. Every read is
//! bounds-checked, and a malformed or unsupported file has no imports instead of being an
//! error: one broken binary shouldn't stop a scan. Only 64-bit little-endian files with section
//! headers are read, which covers the amd64 packages scanned.

use std::collections::HashMap;

/// One imported function.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Import {
    /// The file the version is needed from (`libssl.so.3`).
    pub library: String,
    pub name: String,
    /// The version node (`OPENSSL_3.0.0`).
    pub version: String,
}

const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
const SECTION_HEADER: usize = 64;
const SYMBOL: usize = 24;
/// Caps on loop counts that come from the file, so a hostile one can't make the scan spin.
const MAX_VERNEED: usize = 4096;

/// The imports of `data` that come from one of `libraries` (sonames).
pub fn imports(data: &[u8], libraries: &[&str]) -> Vec<Import> {
    parse(data, libraries).unwrap_or_default()
}

struct Section {
    kind: u32,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
}

impl Section {
    fn bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.offset..self.offset.checked_add(self.size)?)
    }
}

fn parse(data: &[u8], libraries: &[&str]) -> Option<Vec<Import>> {
    // ELFCLASS64, ELFDATA2LSB.
    if data.get(..4)? != b"\x7fELF" || *data.get(4)? != 2 || *data.get(5)? != 1 {
        return None;
    }
    let sections = sections(data)?;
    let dynsym = sections.iter().find(|s| s.kind == SHT_DYNSYM)?;
    let dynstr = sections
        .get(usize::try_from(dynsym.link).ok()?)?
        .bytes(data)?;
    let versym = sections
        .iter()
        .find(|s| s.kind == SHT_GNU_VERSYM)?
        .bytes(data)?;
    let verneed = sections.iter().find(|s| s.kind == SHT_GNU_VERNEED)?;
    let needed = versions_needed(data, verneed, &sections)?;

    let (symbols, _) = dynsym.bytes(data)?.as_chunks::<SYMBOL>();
    let mut imports = Vec::new();
    // Symbol 0 is the reserved null symbol.
    for (i, symbol) in symbols.iter().enumerate().skip(1) {
        // st_shndx 0 (SHN_UNDEF): defined elsewhere, so imported.
        if u16_at(symbol, 6)? != 0 {
            continue;
        }
        // The high bit marks a hidden version; the rest indexes the version tables.
        let Some(index) = u16_at(versym, i.checked_mul(2)?) else {
            continue;
        };
        let Some((file, version)) = needed.get(&(index & 0x7fff)) else {
            continue;
        };
        if libraries.contains(&file.as_str()) {
            imports.push(Import {
                library: file.clone(),
                name: c_str(dynstr, u32_at(symbol, 0)?)?,
                version: version.clone(),
            });
        }
    }
    Some(imports)
}

fn sections(data: &[u8]) -> Option<Vec<Section>> {
    let offset = usize::try_from(u64_at(data, 0x28)?).ok()?;
    let entry_size = usize::from(u16_at(data, 0x3a)?);
    if offset == 0 || entry_size < SECTION_HEADER {
        return None;
    }
    let mut count = usize::from(u16_at(data, 0x3c)?);
    if count == 0 {
        // Extended numbering: section 0's sh_size holds the count.
        count = usize::try_from(u64_at(data, offset.checked_add(32)?)?).ok()?;
    }
    // Every header must lie inside the file, which also bounds the count.
    if offset.checked_add(count.checked_mul(entry_size)?)? > data.len() {
        return None;
    }
    (0..count)
        .map(|i| {
            let at = offset.checked_add(i.checked_mul(entry_size)?)?;
            let header = data.get(at..at.checked_add(SECTION_HEADER)?)?;
            Some(Section {
                kind: u32_at(header, 4)?,
                offset: usize::try_from(u64_at(header, 24)?).ok()?,
                size: usize::try_from(u64_at(header, 32)?).ok()?,
                link: u32_at(header, 40)?,
                info: u32_at(header, 44)?,
            })
        })
        .collect()
}

/// Maps each version index in `.gnu.version_r` to (file, version name).
fn versions_needed(
    data: &[u8],
    verneed: &Section,
    sections: &[Section],
) -> Option<HashMap<u16, (String, String)>> {
    let table = verneed.bytes(data)?;
    let strings = sections
        .get(usize::try_from(verneed.link).ok()?)?
        .bytes(data)?;
    let mut needed = HashMap::new();
    let mut at = 0usize;
    let count = usize::try_from(verneed.info).ok()?.min(MAX_VERNEED);
    for _ in 0..count {
        // Elf64_Verneed: vn_version, vn_cnt, vn_file, vn_aux, vn_next.
        let aux_count = u16_at(table, at.checked_add(2)?)?;
        let file = c_str(strings, u32_at(table, at.checked_add(4)?)?)?;
        let mut aux = at.checked_add(usize::try_from(u32_at(table, at.checked_add(8)?)?).ok()?)?;
        for _ in 0..aux_count {
            // Elf64_Vernaux: vna_hash, vna_flags, vna_other, vna_name, vna_next.
            let index = u16_at(table, aux.checked_add(6)?)?;
            let name = c_str(strings, u32_at(table, aux.checked_add(8)?)?)?;
            needed.insert(index, (file.clone(), name));
            let next = u32_at(table, aux.checked_add(12)?)?;
            if next == 0 {
                break;
            }
            aux = aux.checked_add(usize::try_from(next).ok()?)?;
        }
        let next = u32_at(table, at.checked_add(12)?)?;
        if next == 0 {
            break;
        }
        at = at.checked_add(usize::try_from(next).ok()?)?;
    }
    Some(needed)
}

/// The NUL-terminated string at `offset` in a string table.
fn c_str(table: &[u8], offset: u32) -> Option<String> {
    let rest = table.get(usize::try_from(offset).ok()?..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    String::from_utf8(rest.get(..end)?.to_vec()).ok()
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal ELF64 file with the sections the reader uses. `symbols` are
    /// (name, defined, version index); `needed` are (file, [(version name, index)]).
    pub fn build(symbols: &[(&str, bool, u16)], needed: &[(&str, &[(&str, u16)])]) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut string = |s: &str| {
            let at = u32::try_from(strings.len()).unwrap();
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let mut dynsym = vec![0u8; SYMBOL];
        let mut versym = vec![0u8; 2];
        for (name, defined, version) in symbols {
            let mut symbol = [0u8; SYMBOL];
            symbol[..4].copy_from_slice(&string(name).to_le_bytes());
            symbol[4] = 0x12; // STB_GLOBAL, STT_FUNC
            let shndx: u16 = if *defined { 9 } else { 0 };
            symbol[6..8].copy_from_slice(&shndx.to_le_bytes());
            dynsym.extend_from_slice(&symbol);
            versym.extend_from_slice(&version.to_le_bytes());
        }
        let mut verneed = Vec::new();
        for (i, (file, versions)) in needed.iter().enumerate() {
            let size = 16 + 16 * versions.len();
            let next = if i + 1 == needed.len() { 0 } else { size };
            let mut entry = vec![0u8; 16];
            entry[..2].copy_from_slice(&1u16.to_le_bytes());
            entry[2..4].copy_from_slice(&u16::try_from(versions.len()).unwrap().to_le_bytes());
            entry[4..8].copy_from_slice(&string(file).to_le_bytes());
            entry[8..12].copy_from_slice(&16u32.to_le_bytes());
            entry[12..16].copy_from_slice(&u32::try_from(next).unwrap().to_le_bytes());
            for (j, (version, index)) in versions.iter().enumerate() {
                let mut aux = [0u8; 16];
                aux[6..8].copy_from_slice(&index.to_le_bytes());
                aux[8..12].copy_from_slice(&string(version).to_le_bytes());
                let next: u32 = if j + 1 == versions.len() { 0 } else { 16 };
                aux[12..16].copy_from_slice(&next.to_le_bytes());
                entry.extend_from_slice(&aux);
            }
            verneed.extend_from_slice(&entry);
        }

        // Layout: ELF header, the four section bodies, then five section headers
        // (null, .dynstr, .dynsym, .gnu.version, .gnu.version_r).
        let mut file = vec![0u8; 64];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        let mut place = |body: &[u8]| {
            let at = file.len();
            file.extend_from_slice(body);
            (at, body.len())
        };
        let bodies = [
            (3u32, place(&strings), 0u32, 0u32),
            (SHT_DYNSYM, place(&dynsym), 1, 1),
            (SHT_GNU_VERSYM, place(&versym), 2, 0),
            (
                SHT_GNU_VERNEED,
                place(&verneed),
                1,
                u32::try_from(needed.len()).unwrap(),
            ),
        ];
        let shoff = file.len();
        file.extend_from_slice(&[0u8; SECTION_HEADER]);
        for (kind, (offset, size), link, info) in bodies {
            let mut header = [0u8; SECTION_HEADER];
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            header[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            header[40..44].copy_from_slice(&link.to_le_bytes());
            header[44..48].copy_from_slice(&info.to_le_bytes());
            file.extend_from_slice(&header);
        }
        file[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        file[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        file[0x3c..0x3e].copy_from_slice(&5u16.to_le_bytes());
        file
    }

    const OPENSSL: &[&str] = &["libssl.so.3", "libcrypto.so.3"];

    fn import(library: &str, name: &str, version: &str) -> Import {
        Import {
            library: library.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn reads_versioned_imports_from_the_wanted_libraries() {
        let elf = build(
            &[
                ("SSL_new", false, 2),
                ("EVP_MD_fetch", false, 3),
                ("printf", false, 4),
                ("my_function", true, 1),
                ("SSL_CTX_new", false, 0x8002),
                ("unversioned", false, 1),
            ],
            &[
                ("libssl.so.3", &[("OPENSSL_3.0.0", 2)]),
                (
                    "libcrypto.so.3",
                    &[("OPENSSL_3.0.0", 5), ("OPENSSL_3.4.0", 3)],
                ),
                ("libc.so.6", &[("GLIBC_2.2.5", 4)]),
            ],
        );
        assert_eq!(
            imports(&elf, OPENSSL),
            [
                import("libssl.so.3", "SSL_new", "OPENSSL_3.0.0"),
                import("libcrypto.so.3", "EVP_MD_fetch", "OPENSSL_3.4.0"),
                import("libssl.so.3", "SSL_CTX_new", "OPENSSL_3.0.0"),
            ]
        );
        assert_eq!(imports(&elf, &["libc.so.6"]).len(), 1);
    }

    #[test]
    fn malformed_files_have_no_imports() {
        let elf = build(
            &[("SSL_new", false, 2)],
            &[("libssl.so.3", &[("OPENSSL_3.0.0", 2)])],
        );
        assert_eq!(imports(&elf, OPENSSL).len(), 1);
        // Every truncation, and every single corrupted byte, must be handled without panicking.
        for len in 0..elf.len() {
            let _ = imports(&elf[..len], OPENSSL);
        }
        for at in 0..elf.len() {
            for value in [0x00, 0x7f, 0xff] {
                let mut corrupt = elf.clone();
                corrupt[at] = value;
                let _ = imports(&corrupt, OPENSSL);
            }
        }
        let mut big_endian = elf.clone();
        big_endian[5] = 2;
        assert!(imports(&big_endian, OPENSSL).is_empty());
        assert!(imports(b"#!/bin/sh\n", OPENSSL).is_empty());
    }
}
