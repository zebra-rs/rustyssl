//! The method store (`crypto/property/property.c`): the implementations providers offer of
//! each algorithm (by method number: name number and operation), each with its provider and
//! property definition, and the choice of one for a property query.
//!
//! A query picks, in the order implementations were added, the first that matches without an
//! optional property, or the one matching the most when the query has optional ones. Choices
//! are cached per query text and provider until the store changes. Methods are anything
//! cloneable: a clone is a reference, as OpenSSL's `up_ref`.

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::property::{self, List};

/// One provider's implementation of an algorithm.
struct Implementation<M, P> {
    provider: P,
    /// The definition text, which identifies it with the provider (OpenSSL compares the parsed
    /// lists it caches per text).
    definition: Vec<u8>,
    properties: List,
    method: M,
}

/// An algorithm's implementations and cached choices.
struct Algorithm<M, P> {
    implementations: Vec<Implementation<M, P>>,
    /// Choices by query text: each with the provider it was made for.
    cache: HashMap<Vec<u8>, Vec<(P, M)>>,
}

impl<M, P> Default for Algorithm<M, P> {
    fn default() -> Self {
        Self {
            implementations: Vec::new(),
            cache: HashMap::new(),
        }
    }
}

/// `IMPL_CACHE_FLUSH_THRESHOLD`: cached choices before the cache is emptied.
const CACHE_FLUSH_THRESHOLD: usize = 500;

/// A method store.
pub struct MethodStore<M, P> {
    /// By method number, in OpenSSL's sparse-array order.
    algorithms: BTreeMap<u32, Algorithm<M, P>>,
    cached: usize,
}

impl<M, P> Default for MethodStore<M, P> {
    fn default() -> Self {
        Self {
            algorithms: BTreeMap::new(),
            cached: 0,
        }
    }
}

impl<M: Clone, P: Copy + Eq> MethodStore<M, P> {
    /// `ossl_method_store_add`: adds `method` for `number` from `provider`, unless that
    /// provider already gave one with the same definition. False if it wasn't added.
    pub fn add(
        &mut self,
        provider: P,
        number: u32,
        definition: &[u8],
        properties: List,
        method: M,
    ) -> bool {
        if number == 0 {
            return false;
        }
        self.flush(number);
        let alg = self.algorithms.entry(number).or_default();
        if alg
            .implementations
            .iter()
            .any(|i| i.provider == provider && i.definition == definition)
        {
            return false;
        }
        alg.implementations.push(Implementation {
            provider,
            definition: definition.to_vec(),
            properties,
            method,
        });
        true
    }

    /// `ossl_method_store_fetch`: the implementation of `number` for the (merged) query, from
    /// `provider` if given, with its provider. `None` for no query takes the first.
    pub fn fetch(&self, number: u32, query: Option<&List>, provider: Option<P>) -> Option<(M, P)> {
        let alg = self.algorithms.get(&number)?;
        let candidates = alg
            .implementations
            .iter()
            .filter(|i| provider.is_none_or(|p| p == i.provider));
        let Some(query) = query else {
            return candidates.map(|i| (i.method.clone(), i.provider)).next();
        };
        let mut best: Option<&Implementation<M, P>> = None;
        let mut best_score = -1;
        for i in candidates {
            let score = property::match_count(query, &i.properties);
            if score > best_score {
                best = Some(i);
                best_score = score;
                if !query.has_optional {
                    break;
                }
            }
        }
        best.map(|i| (i.method.clone(), i.provider))
    }

    /// Whether the store has implementations of `number` (`ossl_method_store_retrieve`).
    pub fn contains(&self, number: u32) -> bool {
        self.algorithms.contains_key(&number)
    }

    /// `ossl_method_store_cache_get`: a cached choice for `number` and the query text, made
    /// for `provider` (any provider's, for none).
    pub fn cache_get(&self, number: u32, query: &[u8], provider: Option<P>) -> Option<M> {
        let entries = self.algorithms.get(&number)?.cache.get(query)?;
        entries
            .iter()
            .find(|(p, _)| provider.is_none_or(|q| q == *p))
            .map(|(_, m)| m.clone())
    }

    /// `ossl_method_store_cache_set`: caches a choice (or removes it, for `None`).
    pub fn cache_set(&mut self, number: u32, query: &[u8], provider: P, method: Option<M>) -> bool {
        if self.cached >= CACHE_FLUSH_THRESHOLD {
            self.flush_all();
        }
        let Some(alg) = self.algorithms.get_mut(&number) else {
            return false;
        };
        let entries = alg.cache.entry(query.to_vec()).or_default();
        let before = entries.len();
        entries.retain(|(p, _)| *p != provider);
        let removed = before.saturating_sub(entries.len());
        if let Some(m) = method {
            entries.push((provider, m));
            if removed == 0 {
                self.cached = self.cached.saturating_add(1);
            }
        } else {
            self.cached = self.cached.saturating_sub(removed);
        }
        true
    }

    /// `ossl_method_cache_flush`: forgets the cached choices for `number`.
    fn flush(&mut self, number: u32) {
        if let Some(alg) = self.algorithms.get_mut(&number) {
            let n: usize = alg.cache.values().map(Vec::len).sum();
            self.cached = self.cached.saturating_sub(n);
            alg.cache.clear();
        }
    }

    /// `ossl_method_store_cache_flush_all`.
    pub fn flush_all(&mut self) {
        for alg in self.algorithms.values_mut() {
            alg.cache.clear();
        }
        self.cached = 0;
    }

    /// `ossl_method_store_remove_all_provided`: drops `provider`'s implementations (and the
    /// cached choices of each algorithm that had one).
    pub fn remove_provider(&mut self, provider: P) {
        let mut flushed = Vec::new();
        for (&number, alg) in &mut self.algorithms {
            let before = alg.implementations.len();
            alg.implementations.retain(|i| i.provider != provider);
            if alg.implementations.len() != before {
                flushed.push(number);
            }
        }
        for number in flushed {
            self.flush(number);
        }
    }

    /// `ossl_method_store_do_all`: every implementation, by method number then as added.
    pub fn all(&self) -> Vec<(u32, M)> {
        self.algorithms
            .iter()
            .flat_map(|(&n, alg)| {
                alg.implementations
                    .iter()
                    .map(move |i| (n, i.method.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::{Strings, parse_definition, parse_query};

    #[test]
    fn picks_by_properties() {
        let mut s = Strings::new();
        let mut store: MethodStore<&str, u8> = MethodStore::default();
        let d = |s: &mut Strings, t: &str| parse_definition(s, t.as_bytes()).list.unwrap();
        let a = d(&mut s, "provider=a,fips=no");
        let b = d(&mut s, "provider=b,fips=yes");
        assert!(store.add(1, 7, b"provider=a,fips=no", a, "A"));
        assert!(store.add(2, 7, b"provider=b,fips=yes", b.clone(), "B"));
        assert!(!store.add(2, 7, b"provider=b,fips=yes", b, "B2"));
        let q = |s: &mut Strings, t: &str| parse_query(s, t.as_bytes(), false).list.unwrap();
        assert_eq!(store.fetch(7, None, None), Some(("A", 1)));
        assert_eq!(
            store.fetch(7, Some(&q(&mut s, "fips=yes")), None),
            Some(("B", 2))
        );
        assert_eq!(
            store.fetch(7, Some(&q(&mut s, "?provider=b")), None),
            Some(("B", 2))
        );
        assert_eq!(store.fetch(7, Some(&q(&mut s, "provider=c")), None), None);
        assert_eq!(store.fetch(7, None, Some(2)), Some(("B", 2)));
        assert!(store.cache_set(7, b"q", 2, Some("B")));
        assert_eq!(store.cache_get(7, b"q", None), Some("B"));
        assert_eq!(store.cache_get(7, b"q", Some(1)), None);
        store.remove_provider(2);
        assert_eq!(store.cache_get(7, b"q", None), None);
        assert_eq!(store.all(), vec![(7, "A")]);
    }
}
