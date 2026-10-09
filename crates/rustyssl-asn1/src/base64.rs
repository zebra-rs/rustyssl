//! Base64 as OpenSSL's `EVP_Encode*`/`EVP_Decode*` do it (`crypto/evp/encode.c`): encoding in
//! lines of 64 characters from 48-octet blocks, decoding a line-oriented stream that skips
//! whitespace and stops at `-`, and the one-shot `EVP_EncodeBlock`/`EVP_DecodeBlock`. Both
//! alphabets are here (the standard one and SRP's).
//!
//! The quirks are OpenSSL's, kept because applications see them: decoding processes a line as
//! soon as it holds a multiple of 4 characters, reports what it decoded before an error, and
//! `EVP_DecodeFinal` counts the padding of its last block by comparing the decoded values (not
//! the characters) with `'='`, so a trailing `9` counts as padding.

/// In [`Ctx::flags`]: no newline after each line (`EVP_ENCODE_CTX_NO_NEWLINES`, internal).
pub const NO_NEWLINES: u32 = 1;
/// In [`Ctx::flags`]: SRP's alphabet (`EVP_ENCODE_CTX_USE_SRP_ALPHABET`, internal).
pub const USE_SRP_ALPHABET: u32 = 2;

/// Octets encoded on a line.
const BLOCK: i32 = 48;

/// The standard alphabet.
const BIN2ASCII: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// SRP's alphabet.
const SRP_BIN2ASCII: &[u8; 64] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

/// `-`, the end of the base64.
const EOF: u8 = 0xF2;
/// Whitespace.
const WS: u8 = 0xE0;
/// Not base64.
const ERROR: u8 = 0xFF;

/// Whether a decoded value is one of the specials (end of line 0xF0, CR 0xF1, EOF, whitespace).
fn not_base64(v: u8) -> bool {
    v | 0x13 == 0xF3
}

/// The standard decoding table (`data_ascii2bin`): a character's value, or one of the specials
/// above. `=` is 0.
#[rustfmt::skip]
static ASCII2BIN: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// SRP's decoding table (`srpdata_ascii2bin`).
#[rustfmt::skip]
static SRP_ASCII2BIN: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2, 0x3E, 0x3F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
    0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// `conv_ascii2bin`.
fn decode_char(c: u8, table: &[u8; 128]) -> u8 {
    if c & 0x80 != 0 {
        return ERROR;
    }
    table.get(usize::from(c)).copied().unwrap_or(ERROR)
}

/// An encoding or decoding context, laid out as OpenSSL's private `evp_Encode_Ctx_st`. Any
/// bit pattern is a valid (if odd) state, as C code can copy or zero it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctx {
    /// Characters (decoding) or octets (encoding) held.
    pub num: i32,
    /// Octets on an encoded line (48), or 0 when decoding.
    pub length: i32,
    /// What is held.
    pub enc_data: [u8; 80],
    /// Unused, kept for the layout.
    pub line_num: i32,
    /// [`NO_NEWLINES`] and [`USE_SRP_ALPHABET`].
    pub flags: u32,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            num: 0,
            length: 0,
            enc_data: [0; 80],
            line_num: 0,
            flags: 0,
        }
    }
}

impl Ctx {
    fn encode_table(&self) -> &'static [u8; 64] {
        if self.flags & USE_SRP_ALPHABET != 0 {
            SRP_BIN2ASCII
        } else {
            BIN2ASCII
        }
    }

    fn decode_table(&self) -> &'static [u8; 128] {
        if self.flags & USE_SRP_ALPHABET != 0 {
            &SRP_ASCII2BIN
        } else {
            &ASCII2BIN
        }
    }

    /// `EVP_EncodeInit`.
    pub fn encode_init(&mut self) {
        self.length = BLOCK;
        self.num = 0;
        self.line_num = 0;
        self.flags = 0;
    }

    /// `EVP_DecodeInit`.
    pub fn decode_init(&mut self) {
        self.num = 0;
        self.length = 0;
        self.line_num = 0;
        self.flags = 0;
    }

    /// The held characters or octets, as far as `num` says and the buffer holds.
    fn held(&self) -> &[u8] {
        let n = usize::try_from(self.num)
            .unwrap_or(0)
            .min(self.enc_data.len());
        self.enc_data.get(..n).unwrap_or(&[])
    }

    /// The line length, within the buffer (OpenSSL asserts it is).
    fn line(&self) -> usize {
        usize::try_from(self.length)
            .unwrap_or(0)
            .min(self.enc_data.len())
    }
}

/// `evp_encodeblock_int`: `input` as base64 with padding, appended to `out` (no NUL).
fn encode_into(out: &mut Vec<u8>, input: &[u8], table: &[u8; 64]) {
    let ch = |v: u32| {
        table
            .get(usize::try_from(v & 0x3f).unwrap_or(0))
            .copied()
            .unwrap_or(b'A')
    };
    for chunk in input.chunks(3) {
        match *chunk {
            [a, b, c] => {
                let l = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
                out.extend([ch(l >> 18), ch(l >> 12), ch(l >> 6), ch(l)]);
            }
            [a, b] => {
                let l = (u32::from(a) << 16) | (u32::from(b) << 8);
                out.extend([ch(l >> 18), ch(l >> 12), ch(l >> 6), b'=']);
            }
            [a] => {
                let l = u32::from(a) << 16;
                out.extend([ch(l >> 18), ch(l >> 12), b'=', b'=']);
            }
            _ => {}
        }
    }
}

/// `EVP_EncodeBlock`: `input` as base64 (no NUL; the caller adds OpenSSL's).
pub fn encode_block(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    encode_into(&mut out, input, BIN2ASCII);
    out
}

/// What [`Ctx::encode_update`] produced.
pub struct Encoded {
    /// The lines written.
    pub out: Vec<u8>,
    /// Whether OpenSSL writes a NUL after them (it does after each line).
    pub nul: bool,
}

impl Ctx {
    /// `EVP_EncodeUpdate`: the complete lines `input` makes with what is held, keeping the
    /// rest. `None` (OpenSSL's 0) for no input or more than `INT_MAX` octets of output.
    pub fn encode_update(&mut self, input: &[u8]) -> Option<Encoded> {
        if input.is_empty() {
            return None;
        }
        let line = self.line();
        let num = usize::try_from(self.num).unwrap_or(0).min(line);
        if line.saturating_sub(num) > input.len() {
            if let Some(slot) = self.enc_data.get_mut(num..num.saturating_add(input.len())) {
                slot.copy_from_slice(input);
            }
            self.num = i32::try_from(num.saturating_add(input.len())).unwrap_or(i32::MAX);
            return Some(Encoded {
                out: Vec::new(),
                nul: false,
            });
        }
        let newline = self.flags & NO_NEWLINES == 0;
        let table = self.encode_table();
        let mut out = Vec::new();
        let mut nul = false;
        let mut rest = input;
        if num != 0 {
            let take = line.saturating_sub(num);
            let (head, tail) = rest.split_at(take.min(rest.len()));
            if let Some(slot) = self.enc_data.get_mut(num..num.saturating_add(head.len())) {
                slot.copy_from_slice(head);
            }
            rest = tail;
            let block = self.enc_data.get(..line).unwrap_or(&[]).to_vec();
            encode_into(&mut out, &block, table);
            self.num = 0;
            if newline {
                out.push(b'\n');
            }
            nul = true;
        }
        if line > 0 {
            while rest.len() >= line && out.len() <= INT_MAX {
                let (block, tail) = rest.split_at(line);
                encode_into(&mut out, block, table);
                rest = tail;
                if newline {
                    out.push(b'\n');
                }
                nul = true;
            }
        }
        if out.len() > INT_MAX {
            return None;
        }
        if let Some(slot) = self.enc_data.get_mut(..rest.len()) {
            slot.copy_from_slice(rest);
        }
        self.num = i32::try_from(rest.len()).unwrap_or(0);
        Some(Encoded { out, nul })
    }

    /// `EVP_EncodeFinal`: the last, short line (with its newline and OpenSSL's NUL), if any.
    pub fn encode_final(&mut self) -> Option<Vec<u8>> {
        if self.num == 0 {
            return None;
        }
        let mut out = Vec::new();
        encode_into(&mut out, self.held(), self.encode_table());
        if self.flags & NO_NEWLINES == 0 {
            out.push(b'\n');
        }
        self.num = 0;
        Some(out)
    }
}

/// `INT_MAX` as a length.
const INT_MAX: usize = 0x7fff_ffff;

/// `evp_decodeblock_int`: a block of characters (whitespace trimmed at the start, specials at
/// the end), a multiple of 4, decoded; the last group short by `eof` octets (-1: count the
/// padding as OpenSSL does). `None` (OpenSSL's -1) for anything else.
fn decode_block_with(input: &[u8], eof: i32, table: &[u8; 128]) -> Option<Vec<u8>> {
    if !(-1..=2).contains(&eof) {
        return None;
    }
    let start = input
        .iter()
        .position(|&c| decode_char(c, table) != WS)
        .unwrap_or(input.len());
    let mut f = input.get(start..).unwrap_or(&[]);
    while f.len() > 3 && f.last().is_some_and(|&c| not_base64(decode_char(c, table))) {
        f = f.get(..f.len().saturating_sub(1)).unwrap_or(&[]);
    }
    if f.len() % 4 != 0 {
        return None;
    }
    if f.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(f.len().saturating_mul(3) / 4);
    let groups: Vec<[u8; 4]> = f.as_chunks::<4>().0.to_vec();
    let (last, body) = groups.split_last()?;
    let value = |group: &[u8; 4]| -> Option<(u32, u8, u8)> {
        let [a, b, c, d] = group.map(|ch| decode_char(ch, table));
        if (a | b | c | d) & 0x80 != 0 {
            return None;
        }
        let l = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        Some((l, c, d))
    };
    for group in body {
        let (l, _, _) = value(group)?;
        out.extend(&l.to_be_bytes()[1..]);
    }
    let (l, c, d) = value(last)?;
    // As OpenSSL compares them: the decoded values, against the character '='.
    let eof = if eof == -1 {
        i32::from(c == b'=').wrapping_add(i32::from(d == b'='))
    } else {
        eof
    };
    let [_, x, y, z] = l.to_be_bytes();
    match eof {
        2 => out.push(x),
        1 => out.extend([x, y]),
        _ => out.extend([x, y, z]),
    }
    Some(out)
}

/// `EVP_DecodeBlock`: decodes `input` (trimmed as OpenSSL trims it), always 3 octets a group,
/// padding included. `None` (OpenSSL's -1) for a bad length or character.
pub fn decode_block(input: &[u8]) -> Option<Vec<u8>> {
    decode_block_with(input, 0, &ASCII2BIN)
}

/// What [`Ctx::decode_update`] produced: OpenSSL's return (-1 error, 0 the end was seen, 1
/// more expected) and the octets decoded, which are reported even on error.
pub struct Decoded {
    pub ret: i32,
    pub out: Vec<u8>,
}

impl Ctx {
    /// `EVP_DecodeUpdate`. `None` is a negative length, which OpenSSL treats as no input
    /// without the end that an empty input signals: a held block is still decoded.
    pub fn decode_update(&mut self, input: Option<&[u8]>) -> Decoded {
        let mut n = usize::try_from(self.num).unwrap_or(0);
        let mut out = Vec::new();
        let mut eof: i32 = 0;
        let held = self.held().to_vec();
        if held.last() == Some(&b'=') {
            eof = 1;
            if held.len() > 1 && held.get(held.len().wrapping_sub(2)) == Some(&b'=') {
                eof = 2;
            }
        }
        let table = self.decode_table();
        let finish = |ctx: &mut Self, n: usize, ret: i32, out: Vec<u8>| {
            ctx.num = i32::try_from(n).unwrap_or(0);
            Decoded { ret, out }
        };
        let input = match input {
            Some([]) => return finish(self, n, 0, out),
            Some(input) => input,
            None => &[],
        };
        let mut seof = false;
        for &c in input {
            let v = decode_char(c, table);
            if v == ERROR {
                return finish(self, n, -1, out);
            }
            if c == b'=' {
                eof = eof.wrapping_add(1);
            } else if eof > 0 && !not_base64(v) {
                return finish(self, n, -1, out);
            }
            if eof > 2 {
                return finish(self, n, -1, out);
            }
            if v == EOF {
                seof = true;
                break;
            }
            if !not_base64(v) {
                if n >= 64 {
                    return finish(self, n, -1, out);
                }
                if let Some(slot) = self.enc_data.get_mut(n) {
                    *slot = c;
                }
                n = n.wrapping_add(1);
            }
            if n == 64 {
                let block = self.enc_data.get(..64).unwrap_or(&[]).to_vec();
                n = 0;
                match decode_block_with(&block, eof, table) {
                    Some(d) if !(d.is_empty() && eof > 0) => out.extend(d),
                    _ => return finish(self, n, -1, out),
                }
            }
        }
        if n > 0 {
            if n % 4 == 0 {
                let block = self.enc_data.get(..n).unwrap_or(&[]).to_vec();
                n = 0;
                match decode_block_with(&block, eof, table) {
                    Some(d) if !(d.is_empty() && eof > 0) => out.extend(d),
                    _ => return finish(self, n, -1, out),
                }
            } else if seof {
                return finish(self, n, -1, out);
            }
        }
        let ret = if seof || (n == 0 && eof > 0) { 0 } else { 1 };
        finish(self, n, ret, out)
    }

    /// `EVP_DecodeFinal`: decodes what is held (padding counted as OpenSSL counts it). `None`
    /// (OpenSSL's -1) if it doesn't decode; nothing held is `Some` of nothing.
    pub fn decode_final(&mut self) -> Option<Vec<u8>> {
        if self.num == 0 {
            return Some(Vec::new());
        }
        let out = decode_block_with(self.held(), -1, self.decode_table())?;
        self.num = 0;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks() {
        assert_eq!(encode_block(b"hello"), b"aGVsbG8=");
        assert_eq!(encode_block(b""), b"");
        assert_eq!(decode_block(b"aGVsbG8="), Some(b"hello\0".to_vec()));
        assert_eq!(decode_block(b"  aGVs\n"), Some(b"hel".to_vec()));
        assert_eq!(decode_block(b"aGV"), None);
        assert_eq!(decode_block(b"a*Vs"), None);
    }

    #[test]
    fn streams() {
        let mut ctx = Ctx::default();
        ctx.encode_init();
        let e = ctx.encode_update(&[0x41; 50]).unwrap();
        assert_eq!(e.out.len(), 65);
        assert!(e.nul);
        assert_eq!(ctx.encode_final().unwrap(), b"QUE=\n");

        let mut ctx = Ctx::default();
        ctx.decode_init();
        let d = ctx.decode_update(Some(b"aGVsbG8=\n"));
        assert_eq!((d.ret, d.out.as_slice()), (0, &b"hello"[..]));
        let mut ctx = Ctx::default();
        ctx.decode_init();
        let d = ctx.decode_update(Some(b"aGVsbG"));
        assert_eq!((d.ret, d.out.len(), ctx.num), (1, 0, 6));
        // "aGVsbG" decodes to 4 octets (the last group's padding counted as none).
        assert_eq!(ctx.decode_final().map(|v| v.len()), None);
    }
}
