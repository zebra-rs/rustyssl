//! The TLS presentation language's encoding: big-endian integers and vectors with 1-, 2-, or
//! 3-octet length prefixes (RFC 8446, section 3). Reading never panics: every read is checked
//! against what is left, and a short or overlong vector is a decode error.

/// Decoding failed: the input ended early, a length ran past its enclosing vector, or octets
/// were left over where the structure must end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed TLS encoding")
    }
}

/// A cursor over untrusted input.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `input`.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// What is left.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// How many octets are left.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rest.len()
    }

    /// Whether nothing is left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next `n` octets.
    ///
    /// # Errors
    /// Fewer than `n` are left.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.rest.len() {
            return Err(DecodeError);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    /// Everything left.
    pub fn take_rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.rest)
    }

    /// An 8-bit integer.
    ///
    /// # Errors
    /// The input ended.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let (&b, tail) = self.rest.split_first().ok_or(DecodeError)?;
        self.rest = tail;
        Ok(b)
    }

    /// A 16-bit integer.
    ///
    /// # Errors
    /// The input ended.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(b);
        Ok(u16::from_be_bytes(a))
    }

    /// A 24-bit integer.
    ///
    /// # Errors
    /// The input ended.
    pub fn u24(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(3)?;
        let mut a = [0u8; 4];
        a.get_mut(1..).ok_or(DecodeError)?.copy_from_slice(b);
        Ok(u32::from_be_bytes(a))
    }

    /// A 32-bit integer.
    ///
    /// # Errors
    /// The input ended.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(u32::from_be_bytes(a))
    }

    /// A 64-bit integer.
    ///
    /// # Errors
    /// The input ended.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// A vector with a 1-octet length, as its own reader.
    ///
    /// # Errors
    /// The length runs past the input.
    pub fn vec8(&mut self) -> Result<Reader<'a>, DecodeError> {
        let n = self.u8()?;
        Ok(Reader::new(self.take(usize::from(n))?))
    }

    /// A vector with a 2-octet length, as its own reader.
    ///
    /// # Errors
    /// The length runs past the input.
    pub fn vec16(&mut self) -> Result<Reader<'a>, DecodeError> {
        let n = self.u16()?;
        Ok(Reader::new(self.take(usize::from(n))?))
    }

    /// A vector with a 3-octet length, as its own reader.
    ///
    /// # Errors
    /// The length runs past the input.
    pub fn vec24(&mut self) -> Result<Reader<'a>, DecodeError> {
        let n = usize::try_from(self.u24()?).map_err(|_| DecodeError)?;
        Ok(Reader::new(self.take(n)?))
    }

    /// Fails unless everything was read.
    ///
    /// # Errors
    /// Octets are left.
    pub fn end(&self) -> Result<(), DecodeError> {
        if self.rest.is_empty() { Ok(()) } else { Err(DecodeError) }
    }
}

/// An output buffer with nested, back-patched length prefixes.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

/// A length prefix awaiting its vector's end (from [`Writer::open`]).
#[derive(Debug)]
#[must_use = "a vector must be closed"]
pub struct Open {
    at: usize,
    width: usize,
}

/// The vector written was too long for its length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

impl Writer {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The octets written.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// The octets written, taken.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// How many octets were written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends octets.
    pub fn put(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Appends an 8-bit integer.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Appends a 16-bit integer.
    pub fn u16(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }

    /// Appends a 24-bit integer (the low 24 bits of `v`).
    pub fn u24(&mut self, v: u32) {
        let b = v.to_be_bytes();
        self.put(b.get(1..).unwrap_or_default());
    }

    /// Appends a 32-bit integer.
    pub fn u32(&mut self, v: u32) {
        self.put(&v.to_be_bytes());
    }

    /// Appends a 64-bit integer.
    pub fn u64(&mut self, v: u64) {
        self.put(&v.to_be_bytes());
    }

    /// Starts a vector with a `width`-octet length prefix (1, 2, or 3), patched by
    /// [`Writer::close`].
    pub fn open(&mut self, width: usize) -> Open {
        let at = self.buf.len();
        self.buf.resize(at.saturating_add(width), 0);
        Open { at, width }
    }

    /// Ends a vector, writing its length into its prefix.
    ///
    /// # Errors
    /// The vector is too long for its prefix.
    pub fn close(&mut self, open: Open) -> Result<(), TooLong> {
        let start = open.at.checked_add(open.width).ok_or(TooLong)?;
        let len = self.buf.len().checked_sub(start).ok_or(TooLong)?;
        let max = match open.width {
            1 => 0xff,
            2 => 0xffff,
            3 => 0x00ff_ffff,
            _ => return Err(TooLong),
        };
        if len > max {
            return Err(TooLong);
        }
        let be = u64::try_from(len).map_err(|_| TooLong)?.to_be_bytes();
        let src = be.get(8usize.saturating_sub(open.width)..).ok_or(TooLong)?;
        self.buf.get_mut(open.at..start).ok_or(TooLong)?.copy_from_slice(src);
        Ok(())
    }

    /// Appends `body` as a vector with a `width`-octet length prefix.
    ///
    /// # Errors
    /// `body` is too long for the prefix.
    pub fn vec(&mut self, width: usize, body: &[u8]) -> Result<(), TooLong> {
        let o = self.open(width);
        self.put(body);
        self.close(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_and_vectors_round_trip() {
        let mut w = Writer::new();
        w.u8(1);
        w.u16(0x0203);
        w.u24(0x0004_0506);
        w.u32(0x0708_090a);
        w.vec(2, b"abc").unwrap();
        let o = w.open(3);
        w.vec(1, b"xy").unwrap();
        w.close(o).unwrap();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u24().unwrap(), 0x0004_0506);
        assert_eq!(r.u32().unwrap(), 0x0708_090a);
        assert_eq!(r.vec16().unwrap().rest(), b"abc");
        let mut inner = r.vec24().unwrap();
        assert_eq!(inner.vec8().unwrap().rest(), b"xy");
        inner.end().unwrap();
        r.end().unwrap();
    }

    #[test]
    fn short_input_is_an_error() {
        assert_eq!(Reader::new(&[0, 5, 1, 2]).vec16().unwrap_err(), DecodeError);
        assert_eq!(Reader::new(&[1]).u16().unwrap_err(), DecodeError);
        assert_eq!(Reader::new(&[]).u8().unwrap_err(), DecodeError);
        assert!(Reader::new(&[0]).end().is_err());
    }

    #[test]
    fn a_vector_too_long_for_its_prefix_fails() {
        let mut w = Writer::new();
        assert_eq!(w.vec(1, &[0; 256]), Err(TooLong));
        assert!(w.vec(1, &[0; 255]).is_ok());
    }
}
