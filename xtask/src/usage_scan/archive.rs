//! Finds the ELF files in a package without unpacking it. Debian and Ubuntu packages are `ar`
//! archives holding a compressed `data.tar`. Fedora's are RPM files: a header, then a
//! compressed cpio archive. The containers are parsed here, in memory, and decompression runs
//! `xz`, `zstd`, `gzip`, or `bzip2`, which read the payload from a file this module writes. No
//! file from a package is written to disk or run.
//!
//! Packages are untrusted input. Every read is bounds-checked and every size is checked before
//! it's used. A file can be at most `MAX_FILE` bytes; anything malformed is an error for that
//! package alone.

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::util::Result;

/// The largest file that's read whole; bigger ELF files are skipped.
const MAX_FILE: u64 = 1 << 30;
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Calls `found` with each ELF file in the Debian package `deb`. `scratch` is a file path the
/// compressed `data.tar` can be written to.
pub fn deb_elf_files(deb: &[u8], scratch: &Path, found: &mut dyn FnMut(&[u8])) -> Result {
    let (name, data) = ar_members(deb)?
        .into_iter()
        .find(|(name, _)| name.starts_with("data.tar"))
        .ok_or("no data.tar member")?;
    let tool = match name.strip_prefix("data.tar") {
        Some(".xz") => Some("xz"),
        Some(".zst") => Some("zstd"),
        Some(".gz") => Some("gzip"),
        Some(".bz2") => Some("bzip2"),
        Some("") => None,
        _ => return Err(format!("unknown member {name}").into()),
    };
    match tool {
        Some(tool) => decompress(tool, data, scratch, &mut |input| {
            tar_elf_files(input, found)
        }),
        None => tar_elf_files(&mut &*data, found),
    }
}

/// Calls `found` with each ELF file in the RPM package `rpm`.
pub fn rpm_elf_files(rpm: &[u8], scratch: &Path, found: &mut dyn FnMut(&[u8])) -> Result {
    let (compressor, payload) = rpm_payload(rpm).ok_or("not a readable RPM package")?;
    let tool = match compressor {
        "zstd" => "zstd",
        "xz" | "lzma" => "xz",
        "gzip" => "gzip",
        "bzip2" => "bzip2",
        other => return Err(format!("unknown payload compressor {other}").into()),
    };
    decompress(tool, payload, scratch, &mut |input| {
        cpio_elf_files(input, found)
    })
}

/// The members of an `ar` archive, as (name, contents).
fn ar_members(data: &[u8]) -> Result<Vec<(String, &[u8])>> {
    let mut rest = data.strip_prefix(b"!<arch>\n").ok_or("not an ar archive")?;
    let mut members = Vec::new();
    while let Some((header, after)) = rest.split_at_checked(60) {
        if header.get(58..60) != Some(b"`\n") {
            return Err("bad ar member header".into());
        }
        let field = |range: std::ops::Range<usize>| -> Result<&str> {
            let bytes = header.get(range).ok_or("short ar header")?;
            Ok(std::str::from_utf8(bytes)?.trim_end())
        };
        let name = field(0..16)?.trim_end_matches('/').to_owned();
        let size: usize = field(48..58)?.parse()?;
        let body = after.get(..size).ok_or("truncated ar member")?;
        members.push((name, body));
        // Members are padded to an even length; the last one may not be.
        rest = after
            .get(size.checked_add(size % 2).ok_or("ar size overflow")?..)
            .unwrap_or(&[]);
    }
    Ok(members)
}

/// The compressor and the compressed payload of an RPM package: after the 96-byte lead come
/// the signature header (padded to 8 bytes) and the main header, whose tag 1125 names the
/// payload compressor.
fn rpm_payload(rpm: &[u8]) -> Option<(&str, &[u8])> {
    const PAYLOAD_COMPRESSOR: u32 = 1125;
    const STRING: u32 = 6;
    if rpm.get(..4)? != [0xed, 0xab, 0xee, 0xdb] {
        return None;
    }
    let signature_len = header_len(rpm, 96)?;
    let main = 96usize
        .checked_add(signature_len)?
        .checked_next_multiple_of(8)?;
    let main_len = header_len(rpm, main)?;
    let entries = usize::try_from(u32_be(rpm, main.checked_add(8)?)?).ok()?;
    let store = main
        .checked_add(16)?
        .checked_add(entries.checked_mul(16)?)?;
    let mut compressor = "gzip"; // rpm's default when the tag is absent
    for i in 0..entries {
        let entry = main.checked_add(16)?.checked_add(i.checked_mul(16)?)?;
        if u32_be(rpm, entry)? == PAYLOAD_COMPRESSOR
            && u32_be(rpm, entry.checked_add(4)?)? == STRING
        {
            let offset = usize::try_from(u32_be(rpm, entry.checked_add(8)?)?).ok()?;
            let text = rpm.get(store.checked_add(offset)?..)?;
            let end = text.iter().position(|b| *b == 0)?;
            compressor = std::str::from_utf8(text.get(..end)?).ok()?;
        }
    }
    Some((compressor, rpm.get(main.checked_add(main_len)?..)?))
}

/// The length of the RPM header structure at `at`: 16 bytes, 16 per index entry, and the store.
fn header_len(rpm: &[u8], at: usize) -> Option<usize> {
    if rpm.get(at..at.checked_add(4)?)? != [0x8e, 0xad, 0xe8, 0x01] {
        return None;
    }
    let entries = usize::try_from(u32_be(rpm, at.checked_add(8)?)?).ok()?;
    let store = usize::try_from(u32_be(rpm, at.checked_add(12)?)?).ok()?;
    16usize
        .checked_add(entries.checked_mul(16)?)?
        .checked_add(store)
}

fn u32_be(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Writes `compressed` to `scratch`, runs `tool -dc` on it, and passes its output to `read`.
fn decompress(
    tool: &str,
    compressed: &[u8],
    scratch: &Path,
    read: &mut dyn FnMut(&mut dyn Read) -> Result,
) -> Result {
    fs::write(scratch, compressed)?;
    let mut child = Command::new(tool)
        .arg("-dc")
        .arg("--")
        .arg(scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run `{tool}`: {e}"))?;
    let result = match child.stdout.take() {
        // Drain what the reader leaves (a tar's trailing padding), or the tool fails writing it.
        Some(mut stdout) => {
            read(&mut stdout).and_then(|()| Ok(io::copy(&mut stdout, &mut io::sink()).map(drop)?))
        }
        None => Err("no stdout".into()),
    };
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    fs::remove_file(scratch)?;
    result?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{tool} -dc` failed ({status})").into())
    }
}

/// Calls `found` with each regular file in a tar stream that starts with the ELF magic. Other
/// files are skipped without being buffered.
fn tar_elf_files(input: &mut dyn Read, found: &mut dyn FnMut(&[u8])) -> Result {
    let mut header = [0u8; 512];
    loop {
        if !read_block(input, &mut header)? || header.iter().all(|b| *b == 0) {
            return Ok(()); // end of the stream, or the end-of-archive block
        }
        let size = tar_size(header.get(124..136).ok_or("short tar header")?)?;
        let padding = size
            .checked_next_multiple_of(512)
            .ok_or("tar size overflow")?
            - size;
        // Type '0' (or NUL, from old tars) and '7' are regular files. Everything else (links,
        // directories, GNU long names, pax headers) is skipped by its size.
        match header.get(156) {
            Some(b'0' | 0 | b'7') => file_entry(input, size, found)?,
            _ => skip(input, size)?,
        }
        skip(input, padding)?;
    }
}

/// Fills `block` from `input`. False at a clean end of stream; an error if it ends mid-block.
fn read_block(input: &mut dyn Read, block: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < block.len() {
        let n = input.read(block.get_mut(filled..).ok_or("block overflow")?)?;
        if n == 0 {
            return if filled == 0 {
                Ok(false)
            } else {
                Err("truncated tar stream".into())
            };
        }
        filled += n;
    }
    Ok(true)
}

/// A tar size field: octal digits, or base-256 when the high bit of the first byte is set.
fn tar_size(field: &[u8]) -> Result<u64> {
    match field.split_first() {
        Some((first, rest)) if first & 0x80 != 0 => {
            let mut size = u64::from(first & 0x7f);
            for byte in rest {
                size = size
                    .checked_mul(256)
                    .and_then(|s| s.checked_add(u64::from(*byte)))
                    .ok_or("tar size overflow")?;
            }
            Ok(size)
        }
        _ => {
            let text = std::str::from_utf8(field)?.trim_matches(|c: char| c == '\0' || c == ' ');
            if text.is_empty() {
                Ok(0)
            } else {
                Ok(u64::from_str_radix(text, 8)?)
            }
        }
    }
}

/// Reads a file of `size` bytes, passing it to `found` if it's an ELF file.
fn file_entry(input: &mut dyn Read, size: u64, found: &mut dyn FnMut(&[u8])) -> Result {
    let magic_len = size.min(4);
    let mut magic = Vec::new();
    input.take(magic_len).read_to_end(&mut magic)?;
    if u64::try_from(magic.len())? != magic_len {
        return Err("truncated file in archive".into());
    }
    let rest = size - magic_len;
    if magic != ELF_MAGIC || size > MAX_FILE {
        return skip(input, rest);
    }
    let mut data = magic;
    data.try_reserve_exact(usize::try_from(rest)?)?;
    input.take(rest).read_to_end(&mut data)?;
    if u64::try_from(data.len())? != size {
        return Err("truncated file in archive".into());
    }
    found(&data);
    Ok(())
}

fn skip(input: &mut dyn Read, len: u64) -> Result {
    let skipped = io::copy(&mut input.take(len), &mut io::sink())?;
    if skipped == len {
        Ok(())
    } else {
        Err("truncated archive".into())
    }
}

/// Calls `found` with each regular file in a cpio stream ("newc" format) that starts with the
/// ELF magic.
fn cpio_elf_files(input: &mut dyn Read, found: &mut dyn FnMut(&[u8])) -> Result {
    loop {
        let mut header = [0u8; 110];
        input
            .read_exact(&mut header)
            .map_err(|_| "truncated cpio stream")?;
        let text = std::str::from_utf8(&header)?;
        if !matches!(text.get(..6), Some("070701" | "070702")) {
            return Err("not a newc cpio stream".into());
        }
        // Thirteen 8-digit hex fields follow the magic.
        let field = |i: usize| -> Result<u64> {
            let at = 6 + 8 * i;
            let digits = text.get(at..at + 8).ok_or("short cpio header")?;
            Ok(u64::from_str_radix(digits, 16)?)
        };
        let mode = field(1)?;
        let size = field(6)?;
        let name_len = field(11)?;
        if name_len > 4096 {
            return Err("cpio name too long".into());
        }
        let mut name = Vec::new();
        input.take(name_len).read_to_end(&mut name)?;
        if u64::try_from(name.len())? != name_len {
            return Err("truncated cpio name".into());
        }
        skip(
            input,
            (110 + name_len).next_multiple_of(4) - (110 + name_len),
        )?;
        if name == b"TRAILER!!!\0" {
            return Ok(());
        }
        if mode & 0o170_000 == 0o100_000 {
            file_entry(input, size, found)?;
        } else {
            skip(input, size)?;
        }
        skip(input, size.next_multiple_of(4) - size)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_entry(out: &mut Vec<u8>, name: &str, kind: u8, body: &[u8]) {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = kind;
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(512), 0);
    }

    fn cpio_entry(out: &mut Vec<u8>, name: &str, mode: u32, body: &[u8]) {
        let name = format!("{name}\0");
        let len = |n: usize| u32::try_from(n).unwrap();
        let fields = [
            0,
            mode,
            0,
            0,
            1,
            0,
            len(body.len()),
            0,
            0,
            0,
            0,
            len(name.len()),
            0,
        ];
        out.extend_from_slice(b"070701");
        for field in fields {
            out.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(4), 0);
    }

    fn collect(run: impl FnOnce(&mut dyn FnMut(&[u8])) -> Result) -> Result<Vec<Vec<u8>>> {
        let mut files = Vec::new();
        run(&mut |data| files.push(data.to_vec()))?;
        Ok(files)
    }

    #[test]
    fn tar_yields_only_regular_elf_files() {
        let elf = b"\x7fELF and the rest of a binary".to_vec();
        let mut tar = Vec::new();
        tar_entry(&mut tar, "./usr/bin/", b'5', b"");
        tar_entry(&mut tar, "./usr/bin/tool", b'0', &elf);
        tar_entry(&mut tar, "./usr/bin/script", b'0', b"#!/bin/sh\n");
        tar_entry(&mut tar, "././@LongLink", b'L', &[b'x'; 700]);
        tar_entry(&mut tar, "./usr/bin/link", b'2', &elf); // a symlink's data is skipped
        tar_entry(&mut tar, "./usr/lib/x", b'0', b"\x7fEL");
        tar.extend_from_slice(&[0u8; 1024]);
        let files = collect(|found| tar_elf_files(&mut tar.as_slice(), found)).unwrap();
        assert_eq!(files, [elf]);

        // A stream without the end-of-archive blocks also ends cleanly; a cut one doesn't.
        let mut short = Vec::new();
        tar_entry(&mut short, "a", b'0', b"\x7fELF");
        assert_eq!(
            collect(|f| tar_elf_files(&mut short.as_slice(), f))
                .unwrap()
                .len(),
            1
        );
        let cut = &short[..600];
        assert!(collect(|f| tar_elf_files(&mut &cut[..], f)).is_err());
    }

    #[test]
    fn tar_sizes() {
        assert_eq!(tar_size(b"00000001750\0").unwrap(), 1000);
        assert_eq!(tar_size(b"     1750 \0\0").unwrap(), 1000);
        assert_eq!(tar_size(b"\0\0\0\0\0\0\0\0\0\0\0\0").unwrap(), 0);
        assert_eq!(
            tar_size(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]).unwrap(),
            256
        );
        assert!(tar_size(&[0xff; 12]).is_err());
        assert!(tar_size(b"0000000017x0").is_err());
    }

    #[test]
    fn cpio_yields_only_regular_elf_files() {
        let elf = b"\x7fELF\x02\x01 body".to_vec();
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, "./usr/bin", 0o040_755, b"");
        cpio_entry(&mut cpio, "./usr/bin/tool", 0o100_755, &elf);
        cpio_entry(&mut cpio, "./usr/share/doc", 0o100_644, b"text");
        cpio_entry(&mut cpio, "./usr/lib/link", 0o120_777, b"\x7fELF");
        cpio_entry(&mut cpio, "TRAILER!!!", 0, b"");
        let files = collect(|found| cpio_elf_files(&mut cpio.as_slice(), found)).unwrap();
        assert_eq!(files, [elf]);
        let cut = &cpio[..cpio.len() - 120];
        assert!(collect(|f| cpio_elf_files(&mut &cut[..], f)).is_err());
        assert!(collect(|f| cpio_elf_files(&mut &b"garbage"[..], f)).is_err());
    }

    #[test]
    fn ar_members_and_padding() {
        let mut ar = b"!<arch>\n".to_vec();
        for (name, body) in [("debian-binary", &b"2.0\n"[..]), ("data.tar", &b"odd"[..])] {
            ar.extend_from_slice(
                format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    100_644,
                    body.len()
                )
                .as_bytes(),
            );
            ar.extend_from_slice(body);
            if body.len() % 2 == 1 {
                ar.push(b'\n');
            }
        }
        let members = ar_members(&ar).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[1], ("data.tar".to_owned(), &b"odd"[..]));
        assert!(ar_members(&ar[..ar.len() - 3]).is_err());
        assert!(ar_members(b"not an archive").is_err());
    }

    #[test]
    fn rpm_payload_follows_the_headers() {
        let header = |entries: &[(u32, u32, u32)], store: &[u8]| {
            let mut out = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
            out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
            for (tag, kind, offset) in entries {
                for value in [*tag, *kind, *offset, 1] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            out.extend_from_slice(store);
            out
        };
        let mut rpm = vec![0xed, 0xab, 0xee, 0xdb];
        rpm.resize(96, 0);
        rpm.extend_from_slice(&header(&[(1000, 7, 0)], b"sig"));
        rpm.resize(rpm.len().next_multiple_of(8), 0);
        rpm.extend_from_slice(&header(&[(1000, 6, 0), (1125, 6, 5)], b"name\0zstd\0"));
        rpm.extend_from_slice(b"PAYLOAD");
        assert_eq!(rpm_payload(&rpm), Some(("zstd", &b"PAYLOAD"[..])));
        for len in 0..rpm.len() - 7 {
            assert!(rpm_payload(&rpm[..len]).is_none(), "{len}");
        }
    }

    #[test]
    fn decompresses_with_the_named_tool() {
        let dir = std::env::temp_dir().join(format!("rustssl-archive-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut tar = Vec::new();
        tar_entry(&mut tar, "bin", b'0', b"\x7fELF!");
        let mut gzip = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = gzip.stdin.take().unwrap();
        std::thread::scope(|s| {
            s.spawn(move || io::Write::write_all(&mut stdin, &tar).unwrap());
        });
        let compressed = gzip.wait_with_output().unwrap().stdout;
        let scratch = dir.join("payload");
        let files = collect(|found| {
            decompress("gzip", &compressed, &scratch, &mut |input| {
                tar_elf_files(input, found)
            })
        })
        .unwrap();
        assert_eq!(files, [b"\x7fELF!".to_vec()]);
        assert!(!scratch.exists());
        assert!(decompress("gzip", b"not gzip", &scratch, &mut |_| Ok(())).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
