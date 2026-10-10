//! A library context's algorithm names (`crypto/core_namemap.c`): each algorithm has a number
//! and its names (`"SHA2-256:SHA-256:SHA256"` from a provider), in the order they were added.
//!
//! Names are looked up as OpenSSL's hash table keys them: the first 63 octets, each with bit 5
//! cleared (`ossl_ht_strcase`), so letters match without case, and a few other pairs of
//! characters (`[` and `{`, digits and control characters) collide as they do there.

use std::collections::HashMap;

/// The longest key prefix: OpenSSL's key field is 64 octets with a NUL.
const KEY_MAX: usize = 63;

/// Why names couldn't be added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `CRYPTO_R_BAD_ALGORITHM_NAME`: an empty name in a list.
    BadAlgorithmName,
    /// `CRYPTO_R_CONFLICTING_NAMES`, with OpenSSL's data text.
    ConflictingNames(Vec<u8>),
}

/// A context's names.
#[derive(Default)]
pub struct Namemap {
    /// Each number's names, number `n` at `n - 1`.
    names: Vec<Vec<Vec<u8>>>,
    /// The number of each name's key.
    numbers: HashMap<Vec<u8>, u32>,
}

/// `HT_SET_KEY_STRING_CASE`: the key a name is looked up by.
fn key(name: &[u8]) -> Vec<u8> {
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    name.iter()
        .take(end.min(KEY_MAX))
        .map(|&c| c & !0x20)
        .collect()
}

impl Namemap {
    /// Whether no name was added yet.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// `ossl_namemap_name2num`: the name's number, or 0.
    pub fn number(&self, name: &[u8]) -> u32 {
        self.numbers.get(&key(name)).copied().unwrap_or(0)
    }

    /// `ossl_namemap_num2name`: the `idx`th name of `number`.
    pub fn name(&self, number: u32, idx: usize) -> Option<&[u8]> {
        let i = usize::try_from(number).ok()?.checked_sub(1)?;
        self.names.get(i)?.get(idx).map(Vec::as_slice)
    }

    /// The names of `number`, in the order they were added.
    pub fn names(&self, number: u32) -> &[Vec<u8>] {
        usize::try_from(number)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| self.names.get(i))
            .map_or(&[], Vec::as_slice)
    }

    /// `namemap_add_name`: adds `name` to `number` (a new number for 0); a name already known
    /// keeps its number, which is returned. 0 if `name` is empty or the numbers ran out.
    pub fn add_name(&mut self, number: u32, name: &[u8]) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let existing = self.number(name);
        if existing != 0 {
            return existing;
        }
        let number = match usize::try_from(number).ok().and_then(|n| n.checked_sub(1)) {
            Some(i) => match self.names.get_mut(i) {
                Some(names) => {
                    names.push(name.to_vec());
                    number
                }
                None => return 0,
            },
            None => {
                let Some(n) = self
                    .names
                    .len()
                    .checked_add(1)
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|&n| i32::try_from(n).is_ok())
                else {
                    return 0;
                };
                self.names.push(vec![name.to_vec()]);
                n
            }
        };
        self.numbers.insert(key(name), number);
        number
    }

    /// `ossl_namemap_add_names`: adds the names `names` lists (split at `separator`) to one
    /// number: `number`, or the one a name already has, or a new one. Fails if a name is
    /// empty or already belongs to another number.
    pub fn add_names(&mut self, number: u32, names: &[u8], separator: u8) -> Result<u32, Error> {
        let list: Vec<&[u8]> = names.split(|&c| c == separator).collect();
        let mut number = number;
        // A trailing separator ends the list, as OpenSSL's loop stops at the NUL.
        let count = if names.last() == Some(&separator) {
            list.len().saturating_sub(1)
        } else if names.is_empty() {
            0
        } else {
            list.len()
        };
        for &name in list.iter().take(count) {
            if name.is_empty() {
                return Err(Error::BadAlgorithmName);
            }
            let this = self.number(name);
            if number == 0 {
                number = this;
            } else if this != 0 && this != number {
                let mut data = b"\"".to_vec();
                data.extend_from_slice(name);
                data.extend_from_slice(
                    format!("\" has an existing different identity {this} (from \"").as_bytes(),
                );
                data.extend_from_slice(names);
                data.extend_from_slice(b"\")");
                return Err(Error::ConflictingNames(data));
            }
        }
        for &name in list.iter().take(count) {
            let this = self.add_name(number, name);
            if number == 0 {
                number = this;
            }
        }
        Ok(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers() {
        let mut m = Namemap::default();
        assert_eq!(m.add_names(0, b"SHA2-256:SHA-256:SHA256", b':'), Ok(1));
        assert_eq!(m.number(b"sha256"), 1);
        assert_eq!(m.number(b"Sha-256"), 1);
        assert_eq!(m.add_names(0, b"MD5:SSL3-MD5", b':'), Ok(2));
        assert_eq!(m.add_names(0, b"sha256:new-alias", b':'), Ok(1));
        assert_eq!(m.names(1).len(), 4);
        assert_eq!(m.name(1, 0), Some(&b"SHA2-256"[..]));
        assert!(matches!(
            m.add_names(0, b"MD5:SHA256", b':'),
            Err(Error::ConflictingNames(_))
        ));
        assert_eq!(m.add_names(0, b"A::B", b':'), Err(Error::BadAlgorithmName));
        assert_eq!(m.add_names(0, b"x:", b':'), Ok(3));
        // OpenSSL's keys clear bit 5: `[` and `{` collide.
        assert_eq!(m.add_names(0, b"a[b", b':'), Ok(4));
        assert_eq!(m.number(b"A{B"), 4);
        let long = [b'n'; 70];
        assert_eq!(m.add_name(0, &long), 5);
        assert_eq!(m.number(&long[..63]), 5);
    }
}
