//! Reads an ELF file's dynamic linking information: which functions it imports from given
//! libraries (for `usage-scan`), and what a shared library exports, which versions it defines,
//! and what it depends on (for `abi-check`).
//!
//! An import is an undefined dynamic symbol whose GNU symbol version (`.gnu.version`) names a
//! version that `.gnu.version_r` says comes from a given file (`SSL_new@OPENSSL_3.0.0` from
//! `libssl.so.3`). An export is a defined global symbol, with the version `.gnu.version_d`
//! defines for it.
//!
//! Files can come from downloaded packages, so they're untrusted input. Every read is
//! bounds-checked, and loop counts taken from the file are capped. A malformed file is `None`
//! (or has no imports), never a panic. Only 64-bit little-endian files with section headers are
//! read, which covers every platform rustssl builds ELF libraries for.

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

/// One exported symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    /// The version node it's defined in, if it has one.
    pub version: Option<String>,
    /// A non-default version (`name@VERSION` rather than `name@@VERSION`).
    pub hidden: bool,
    /// Defined as an absolute value rather than in a section, as linkers do for the symbol that
    /// names each version node.
    pub absolute: bool,
}

/// One version node a library defines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionDefinition {
    pub name: String,
    /// The nodes it inherits from (`} OPENSSL_3.0.0;` in the version script).
    pub parents: Vec<String>,
    /// The library's own base version, named after its soname.
    pub base: bool,
}

/// A shared library's dynamic linking information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Library {
    pub soname: Option<String>,
    /// `DT_NEEDED`: the libraries it depends on.
    pub needed: Vec<String>,
    pub versions: Vec<VersionDefinition>,
    pub exports: Vec<Export>,
}

const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
const SHN_ABS: u16 = 0xfff1;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_SONAME: u64 = 14;
const SECTION_HEADER: usize = 64;
const SYMBOL: usize = 24;
const DYNAMIC_ENTRY: usize = 16;
/// The most version entries read from one table, so a hostile file can't make a loop spin.
const MAX_VERSIONS: usize = 4096;

/// The imports of `data` that come from one of `libraries` (sonames).
pub fn imports(data: &[u8], libraries: &[&str]) -> Vec<Import> {
    read_imports(data, libraries).unwrap_or_default()
}

/// The exports, version definitions, and dependencies of the shared library `data`.
pub fn library(data: &[u8]) -> Option<Library> {
    let elf = Elf::open(data)?;
    let definitions = elf.version_definitions()?;
    let names: HashMap<u16, &str> = definitions
        .iter()
        .map(|(index, definition)| (*index, definition.name.as_str()))
        .collect();
    let strings = elf.dynamic_strings()?;
    let mut exports = Vec::new();
    for symbol in elf.symbols()? {
        // Defined (not SHN_UNDEF); global, weak, or GNU-unique; default or protected visibility.
        if symbol.section == 0
            || !matches!(symbol.info >> 4, 1 | 2 | 10)
            || !matches!(symbol.other & 3, 0 | 3)
        {
            continue;
        }
        // Version index 0 is local and 1 the unversioned global; definitions start at 1 with
        // the base version, so only indexes from 2 name a node.
        let index = symbol.version & 0x7fff;
        exports.push(Export {
            name: c_str(strings, symbol.name)?,
            version: (index >= 2)
                .then(|| names.get(&index).map(|n| (*n).to_owned()))
                .flatten(),
            hidden: symbol.version & 0x8000 != 0,
            absolute: symbol.section == SHN_ABS,
        });
    }
    let (soname, needed) = elf.dynamic()?;
    Some(Library {
        soname,
        needed,
        versions: definitions.into_iter().map(|(_, d)| d).collect(),
        exports,
    })
}

fn read_imports(data: &[u8], libraries: &[&str]) -> Option<Vec<Import>> {
    let elf = Elf::open(data)?;
    let needed = elf.versions_needed()?;
    let strings = elf.dynamic_strings()?;
    let mut imports = Vec::new();
    for symbol in elf.symbols()? {
        // SHN_UNDEF: defined elsewhere, so imported.
        if symbol.section != 0 {
            continue;
        }
        let Some((file, version)) = needed.get(&(symbol.version & 0x7fff)) else {
            continue;
        };
        if libraries.contains(&file.as_str()) {
            imports.push(Import {
                library: file.clone(),
                name: c_str(strings, symbol.name)?,
                version: version.clone(),
            });
        }
    }
    Some(imports)
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

/// A dynamic symbol's fields that matter here, with its `.gnu.version` entry.
struct Symbol {
    name: u32,
    info: u8,
    other: u8,
    section: u16,
    version: u16,
}

struct Elf<'a> {
    data: &'a [u8],
    sections: Vec<Section>,
}

impl<'a> Elf<'a> {
    fn open(data: &'a [u8]) -> Option<Self> {
        // ELFCLASS64, ELFDATA2LSB.
        if data.get(..4)? != b"\x7fELF" || *data.get(4)? != 2 || *data.get(5)? != 1 {
            return None;
        }
        Some(Self {
            data,
            sections: sections(data)?,
        })
    }

    fn section(&self, kind: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.kind == kind)
    }

    /// The string table a section's `sh_link` names.
    fn linked_strings(&self, section: &Section) -> Option<&'a [u8]> {
        self.sections
            .get(usize::try_from(section.link).ok()?)?
            .bytes(self.data)
    }

    fn dynamic_strings(&self) -> Option<&'a [u8]> {
        self.linked_strings(self.section(SHT_DYNSYM)?)
    }

    /// The dynamic symbols after the reserved null symbol, each with its version entry (1, the
    /// unversioned global, if the file has no `.gnu.version`).
    fn symbols(&self) -> Option<Vec<Symbol>> {
        let versym = match self.section(SHT_GNU_VERSYM) {
            Some(section) => Some(section.bytes(self.data)?),
            None => None,
        };
        let (symbols, _) = self
            .section(SHT_DYNSYM)?
            .bytes(self.data)?
            .as_chunks::<SYMBOL>();
        symbols
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, symbol)| {
                Some(Symbol {
                    name: u32_at(symbol, 0)?,
                    info: *symbol.get(4)?,
                    other: *symbol.get(5)?,
                    section: u16_at(symbol, 6)?,
                    version: match versym {
                        Some(table) => u16_at(table, i.checked_mul(2)?)?,
                        None => 1,
                    },
                })
            })
            .collect()
    }

    /// Maps each version index in `.gnu.version_r` to (file, version name).
    fn versions_needed(&self) -> Option<HashMap<u16, (String, String)>> {
        let mut needed = HashMap::new();
        let Some(verneed) = self.section(SHT_GNU_VERNEED) else {
            return Some(needed);
        };
        let table = verneed.bytes(self.data)?;
        let strings = self.linked_strings(verneed)?;
        let mut at = 0usize;
        let count = usize::try_from(verneed.info).ok()?.min(MAX_VERSIONS);
        for _ in 0..count {
            // Elf64_Verneed: vn_version, vn_cnt, vn_file, vn_aux, vn_next.
            let aux_count = u16_at(table, at.checked_add(2)?)?;
            let file = c_str(strings, u32_at(table, at.checked_add(4)?)?)?;
            let mut aux =
                at.checked_add(usize::try_from(u32_at(table, at.checked_add(8)?)?).ok()?)?;
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

    /// The versions in `.gnu.version_d`, in file order, with their indexes.
    fn version_definitions(&self) -> Option<Vec<(u16, VersionDefinition)>> {
        let mut definitions = Vec::new();
        let Some(verdef) = self.section(SHT_GNU_VERDEF) else {
            return Some(definitions);
        };
        let table = verdef.bytes(self.data)?;
        let strings = self.linked_strings(verdef)?;
        let mut at = 0usize;
        let count = usize::try_from(verdef.info).ok()?.min(MAX_VERSIONS);
        for _ in 0..count {
            // Elf64_Verdef: vd_version, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next.
            let flags = u16_at(table, at.checked_add(2)?)?;
            let index = u16_at(table, at.checked_add(4)?)?;
            let name_count = u16_at(table, at.checked_add(6)?)?;
            let mut aux =
                at.checked_add(usize::try_from(u32_at(table, at.checked_add(12)?)?).ok()?)?;
            let mut names = Vec::new();
            for _ in 0..name_count {
                // Elf64_Verdaux: vda_name, vda_next. The first names the version, the rest
                // its parents.
                names.push(c_str(strings, u32_at(table, aux)?)?);
                let next = u32_at(table, aux.checked_add(4)?)?;
                if next == 0 {
                    break;
                }
                aux = aux.checked_add(usize::try_from(next).ok()?)?;
            }
            let (name, parents) = names.split_first()?;
            definitions.push((
                index,
                VersionDefinition {
                    name: name.clone(),
                    parents: parents.to_vec(),
                    base: flags & 1 != 0,
                },
            ));
            let next = u32_at(table, at.checked_add(16)?)?;
            if next == 0 {
                break;
            }
            at = at.checked_add(usize::try_from(next).ok()?)?;
        }
        Some(definitions)
    }

    /// `DT_SONAME` and the `DT_NEEDED` entries, in order.
    fn dynamic(&self) -> Option<(Option<String>, Vec<String>)> {
        let mut soname = None;
        let mut needed = Vec::new();
        let Some(dynamic) = self.section(SHT_DYNAMIC) else {
            return Some((soname, needed));
        };
        let strings = self.linked_strings(dynamic)?;
        let (entries, _) = dynamic.bytes(self.data)?.as_chunks::<DYNAMIC_ENTRY>();
        for entry in entries {
            let value = || c_str(strings, u32::try_from(u64_at(entry, 8)?).ok()?);
            match u64_at(entry, 0)? {
                DT_NULL => break,
                DT_NEEDED => needed.push(value()?),
                DT_SONAME => soname = Some(value()?),
                _ => {}
            }
        }
        Some((soname, needed))
    }
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
mod tests {
    use super::*;

    /// What a test ELF file holds.
    #[derive(Default)]
    struct Spec<'a> {
        /// (name, section index (0 = undefined), version entry).
        symbols: &'a [(&'a str, u16, u16)],
        /// (file, [(version, index)]).
        needed: &'a [(&'a str, &'a [(&'a str, u16)])],
        /// (index, base, [version, parents...]).
        defined: &'a [(u16, bool, &'a [&'a str])],
        /// (tag, string).
        dynamic: &'a [(u64, &'a str)],
    }

    /// A minimal ELF64 file with the sections the reader uses.
    fn build(spec: &Spec) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut string = |s: &str| {
            let at = u32::try_from(strings.len()).unwrap();
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let mut dynsym = vec![0u8; SYMBOL];
        let mut versym = vec![0u8; 2];
        for (name, section, version) in spec.symbols {
            let mut symbol = [0u8; SYMBOL];
            symbol[..4].copy_from_slice(&string(name).to_le_bytes());
            symbol[4] = 0x12; // STB_GLOBAL, STT_FUNC
            symbol[6..8].copy_from_slice(&section.to_le_bytes());
            dynsym.extend_from_slice(&symbol);
            versym.extend_from_slice(&version.to_le_bytes());
        }
        let mut verneed = Vec::new();
        for (i, (file, versions)) in spec.needed.iter().enumerate() {
            let size = 16 + 16 * versions.len();
            let next = if i + 1 == spec.needed.len() { 0 } else { size };
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
        let mut verdef = Vec::new();
        for (i, (index, base, names)) in spec.defined.iter().enumerate() {
            let size = 20 + 8 * names.len();
            let next = if i + 1 == spec.defined.len() { 0 } else { size };
            let mut entry = vec![0u8; 20];
            entry[..2].copy_from_slice(&1u16.to_le_bytes());
            entry[2..4].copy_from_slice(&u16::from(*base).to_le_bytes());
            entry[4..6].copy_from_slice(&index.to_le_bytes());
            entry[6..8].copy_from_slice(&u16::try_from(names.len()).unwrap().to_le_bytes());
            entry[12..16].copy_from_slice(&20u32.to_le_bytes());
            entry[16..20].copy_from_slice(&u32::try_from(next).unwrap().to_le_bytes());
            for (j, name) in names.iter().enumerate() {
                let mut aux = [0u8; 8];
                aux[..4].copy_from_slice(&string(name).to_le_bytes());
                let next: u32 = if j + 1 == names.len() { 0 } else { 8 };
                aux[4..8].copy_from_slice(&next.to_le_bytes());
                entry.extend_from_slice(&aux);
            }
            verdef.extend_from_slice(&entry);
        }
        let mut dynamic = Vec::new();
        for (tag, value) in spec.dynamic.iter().chain([&(DT_NULL, "")]) {
            let value = if *tag == DT_NULL { 0 } else { string(value) };
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&u64::from(value).to_le_bytes());
        }

        // Layout: ELF header, the section bodies, then the section headers: null, .dynstr,
        // .dynsym, .gnu.version, .gnu.version_r, .gnu.version_d, .dynamic.
        let mut file = vec![0u8; 64];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        let mut place = |body: &[u8]| {
            let at = file.len();
            file.extend_from_slice(body);
            (at, body.len())
        };
        let count = |n: usize| u32::try_from(n).unwrap();
        let bodies = [
            (3u32, place(&strings), 0u32, 0u32),
            (SHT_DYNSYM, place(&dynsym), 1, 1),
            (SHT_GNU_VERSYM, place(&versym), 2, 0),
            (
                SHT_GNU_VERNEED,
                place(&verneed),
                1,
                count(spec.needed.len()),
            ),
            (SHT_GNU_VERDEF, place(&verdef), 1, count(spec.defined.len())),
            (SHT_DYNAMIC, place(&dynamic), 1, 0),
        ];
        let shoff = file.len();
        file.extend_from_slice(&[0u8; SECTION_HEADER]);
        for (kind, (offset, size), link, info) in bodies {
            let mut header = [0u8; SECTION_HEADER];
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[24..32].copy_from_slice(&u64::try_from(offset).unwrap().to_le_bytes());
            header[32..40].copy_from_slice(&u64::try_from(size).unwrap().to_le_bytes());
            header[40..44].copy_from_slice(&link.to_le_bytes());
            header[44..48].copy_from_slice(&info.to_le_bytes());
            file.extend_from_slice(&header);
        }
        file[0x28..0x30].copy_from_slice(&u64::try_from(shoff).unwrap().to_le_bytes());
        file[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        file[0x3c..0x3e].copy_from_slice(&7u16.to_le_bytes());
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

    fn program() -> Vec<u8> {
        build(&Spec {
            symbols: &[
                ("SSL_new", 0, 2),
                ("EVP_MD_fetch", 0, 3),
                ("printf", 0, 4),
                ("my_function", 9, 1),
                ("SSL_CTX_new", 0, 0x8002),
                ("unversioned", 0, 1),
            ],
            needed: &[
                ("libssl.so.3", &[("OPENSSL_3.0.0", 2)]),
                (
                    "libcrypto.so.3",
                    &[("OPENSSL_3.0.0", 5), ("OPENSSL_3.4.0", 3)],
                ),
                ("libc.so.6", &[("GLIBC_2.2.5", 4)]),
            ],
            ..Spec::default()
        })
    }

    fn shared_library() -> Vec<u8> {
        build(&Spec {
            symbols: &[
                ("OPENSSL_3.0.0", SHN_ABS, 2),
                ("SSL_new", 9, 2),
                ("SSL_new_ex", 9, 3),
                ("SSL_old", 9, 0x8002),
                ("malloc", 0, 1),
            ],
            defined: &[
                (1, true, &["libssl.so.3"]),
                (2, false, &["OPENSSL_3.0.0"]),
                (3, false, &["OPENSSL_3.2.0", "OPENSSL_3.0.0"]),
            ],
            dynamic: &[
                (DT_NEEDED, "libcrypto.so.3"),
                (DT_SONAME, "libssl.so.3"),
                (DT_NEEDED, "libc.so.6"),
            ],
            ..Spec::default()
        })
    }

    #[test]
    fn reads_versioned_imports_from_the_wanted_libraries() {
        let elf = program();
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
    fn reads_a_shared_library() {
        let library = library(&shared_library()).unwrap();
        assert_eq!(library.soname.as_deref(), Some("libssl.so.3"));
        assert_eq!(library.needed, ["libcrypto.so.3", "libc.so.6"]);
        let versions: Vec<(&str, Vec<&str>, bool)> = library
            .versions
            .iter()
            .map(|v| {
                (
                    v.name.as_str(),
                    v.parents.iter().map(String::as_str).collect(),
                    v.base,
                )
            })
            .collect();
        assert_eq!(
            versions,
            [
                ("libssl.so.3", vec![], true),
                ("OPENSSL_3.0.0", vec![], false),
                ("OPENSSL_3.2.0", vec!["OPENSSL_3.0.0"], false),
            ]
        );
        let export = |name: &str, version: &str, hidden: bool, absolute: bool| Export {
            name: name.to_owned(),
            version: Some(version.to_owned()),
            hidden,
            absolute,
        };
        assert_eq!(
            library.exports,
            [
                export("OPENSSL_3.0.0", "OPENSSL_3.0.0", false, true),
                export("SSL_new", "OPENSSL_3.0.0", false, false),
                export("SSL_new_ex", "OPENSSL_3.2.0", false, false),
                export("SSL_old", "OPENSSL_3.0.0", true, false),
            ]
        );
    }

    #[test]
    fn malformed_files_are_handled() {
        for elf in [program(), shared_library()] {
            // Every truncation, and every single corrupted byte, must be handled without
            // panicking.
            for len in 0..elf.len() {
                let _ = imports(&elf[..len], OPENSSL);
                let _ = library(&elf[..len]);
            }
            for at in 0..elf.len() {
                for value in [0x00, 0x7f, 0xff] {
                    let mut corrupt = elf.clone();
                    corrupt[at] = value;
                    let _ = imports(&corrupt, OPENSSL);
                    let _ = library(&corrupt);
                }
            }
            let mut big_endian = elf.clone();
            big_endian[5] = 2;
            assert!(imports(&big_endian, OPENSSL).is_empty());
            assert!(library(&big_endian).is_none());
        }
        assert!(imports(b"#!/bin/sh\n", OPENSSL).is_empty());
    }
}
