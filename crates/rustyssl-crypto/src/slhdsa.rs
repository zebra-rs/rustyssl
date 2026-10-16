//! SLH-DSA (FIPS 205), its twelve parameter sets over SHA-2 and SHAKE, with OpenSSL's rules (its
//! `slh_dsa` directory): keys from `SK.seed || SK.prf || PK.seed` (the root `PK.root` computed),
//! private keys of `4n` octets and public keys of `2n` taken as given (a pairwise check
//! recomputes the root), and signing and verifying of a message (already encoded, or raw), with
//! the additional randomness given or, for deterministic signing, `PK.seed`.
//!
//! The tweakable hashes are FIPS 205's (11.1 for SHAKE, 11.2 for SHA-2), with the SHA-2 state
//! after `PK.seed` and its zero padding computed once per key. WOTS+, XMSS, the hypertree, and
//! FORS follow FIPS 205's algorithms; their only data-dependent paths (the chains' lengths, the
//! trees' indices) depend on the message digest, which the signature reveals.

use keccak::Keccak;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// The largest `n`.
pub const MAX_N: usize = 32;
/// The largest `m`.
const MAX_M: usize = 49;
/// The longest context string.
pub const MAX_CONTEXT: usize = 255;

/// A hash value: `n` octets used.
type Node = [u8; MAX_N];

/// The ADRS types (FIPS 205 4.2).
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// WOTS+'s `w` less one: a chain's last step.
const W_MAX: u32 = 15;

/// A parameter set's constants (FIPS 205 Table 2).
#[derive(Debug)]
struct Params {
    name: &'static str,
    n: usize,
    /// The hypertree's height `h` and its layers `d`; `hp` is `h' = h / d`.
    h: u32,
    d: u32,
    hp: u32,
    /// FORS: `k` trees of height `a`.
    a: u32,
    k: u32,
    /// The message digest's length.
    m: usize,
    sig_len: usize,
    category: u32,
    shake: bool,
}

/// An SLH-DSA parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
    Shake128s,
    Shake128f,
    Shake192s,
    Shake192f,
    Shake256s,
    Shake256f,
}

/// The parameters by size: `n, h, d, h', a, k, m, signature length, category`.
const fn sizes(
    name: &'static str,
    shake: bool,
    s: (usize, u32, u32, u32, u32, u32, usize, usize, u32),
) -> Params {
    Params {
        name,
        n: s.0,
        h: s.1,
        d: s.2,
        hp: s.3,
        a: s.4,
        k: s.5,
        m: s.6,
        sig_len: s.7,
        category: s.8,
        shake,
    }
}

const S128: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (16, 63, 7, 9, 12, 14, 30, 7856, 1);
const F128: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (16, 66, 22, 3, 6, 33, 34, 17088, 1);
const S192: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (24, 63, 7, 9, 14, 17, 39, 16224, 3);
const F192: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (24, 66, 22, 3, 8, 33, 42, 35664, 3);
const S256: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (32, 64, 8, 8, 14, 22, 47, 29792, 5);
const F256: (usize, u32, u32, u32, u32, u32, usize, usize, u32) =
    (32, 68, 17, 4, 9, 35, 49, 49856, 5);

static SHA2_128S: Params = sizes("SLH-DSA-SHA2-128s", false, S128);
static SHA2_128F: Params = sizes("SLH-DSA-SHA2-128f", false, F128);
static SHA2_192S: Params = sizes("SLH-DSA-SHA2-192s", false, S192);
static SHA2_192F: Params = sizes("SLH-DSA-SHA2-192f", false, F192);
static SHA2_256S: Params = sizes("SLH-DSA-SHA2-256s", false, S256);
static SHA2_256F: Params = sizes("SLH-DSA-SHA2-256f", false, F256);
static SHAKE_128S: Params = sizes("SLH-DSA-SHAKE-128s", true, S128);
static SHAKE_128F: Params = sizes("SLH-DSA-SHAKE-128f", true, F128);
static SHAKE_192S: Params = sizes("SLH-DSA-SHAKE-192s", true, S192);
static SHAKE_192F: Params = sizes("SLH-DSA-SHAKE-192f", true, F192);
static SHAKE_256S: Params = sizes("SLH-DSA-SHAKE-256s", true, S256);
static SHAKE_256F: Params = sizes("SLH-DSA-SHAKE-256f", true, F256);

impl Variant {
    /// Every parameter set, in OpenSSL's order of registration.
    pub const ALL: [Self; 12] = [
        Self::Sha2_128s,
        Self::Sha2_128f,
        Self::Sha2_192s,
        Self::Sha2_192f,
        Self::Sha2_256s,
        Self::Sha2_256f,
        Self::Shake128s,
        Self::Shake128f,
        Self::Shake192s,
        Self::Shake192f,
        Self::Shake256s,
        Self::Shake256f,
    ];

    const fn params(self) -> &'static Params {
        match self {
            Self::Sha2_128s => &SHA2_128S,
            Self::Sha2_128f => &SHA2_128F,
            Self::Sha2_192s => &SHA2_192S,
            Self::Sha2_192f => &SHA2_192F,
            Self::Sha2_256s => &SHA2_256S,
            Self::Sha2_256f => &SHA2_256F,
            Self::Shake128s => &SHAKE_128S,
            Self::Shake128f => &SHAKE_128F,
            Self::Shake192s => &SHAKE_192S,
            Self::Shake192f => &SHAKE_192F,
            Self::Shake256s => &SHAKE_256S,
            Self::Shake256f => &SHAKE_256F,
        }
    }

    /// Its name (`SLH-DSA-SHA2-128s`, ...).
    pub const fn name(self) -> &'static str {
        self.params().name
    }

    /// The security parameter `n`: the length of seeds, hashes, and the randomness.
    pub const fn n(self) -> usize {
        self.params().n
    }

    /// Whether its hashes are SHAKE's.
    pub const fn is_shake(self) -> bool {
        self.params().shake
    }

    /// Its NIST security category (1, 3, or 5).
    pub const fn security_category(self) -> u32 {
        self.params().category
    }

    /// The public key's length, `2n` (`PK.seed || PK.root`).
    pub const fn public_key_bytes(self) -> usize {
        self.params().n.saturating_mul(2)
    }

    /// The private key's length, `4n` (`SK.seed || SK.prf || PK.seed || PK.root`).
    pub const fn private_key_bytes(self) -> usize {
        self.params().n.saturating_mul(4)
    }

    /// The signature's length.
    pub const fn signature_bytes(self) -> usize {
        self.params().sig_len
    }
}

/// The first `n` octets of `node`.
fn prefix(node: &[u8], n: usize) -> &[u8] {
    node.get(..n).unwrap_or_default()
}

/// `toInt` (FIPS 205 Algorithm 1), big-endian, of up to 8 octets.
fn to_int(x: &[u8]) -> u64 {
    x.iter()
        .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b))
}

/// The low `bits` bits set.
fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        1u64.wrapping_shl(bits).wrapping_sub(1)
    }
}

/// `base_2^b` (FIPS 205 Algorithm 4): `out_len` integers of `b` bits from `x`, most significant
/// first.
fn base_2b(x: &[u8], b: u32, out_len: usize) -> Vec<u32> {
    let mut bytes = x.iter();
    let mut bits = 0u32;
    let mut total = 0u64;
    let mut out = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        while bits < b {
            total = total.wrapping_shl(8) | u64::from(bytes.next().copied().unwrap_or(0));
            bits = bits.wrapping_add(8);
        }
        bits = bits.wrapping_sub(b);
        let v = total.wrapping_shr(bits) & mask(b);
        out.push(u32::try_from(v).unwrap_or(0));
        total &= mask(bits);
    }
    out
}

/// An address (FIPS 205 4.2): 32 octets of layer, tree, type, and three words.
#[derive(Clone, Copy, Default)]
struct Adrs([u8; 32]);

impl Adrs {
    fn set_word(&mut self, at: usize, v: u32) {
        if let Some(s) = self.0.get_mut(at..at.saturating_add(4)) {
            s.copy_from_slice(&v.to_be_bytes());
        }
    }

    fn word(&self, at: usize) -> u32 {
        self.0
            .get(at..at.saturating_add(4))
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map_or(0, u32::from_be_bytes)
    }

    fn set_layer(&mut self, layer: u32) {
        self.set_word(0, layer);
    }

    fn set_tree(&mut self, tree: u64) {
        self.set_word(4, 0);
        if let Some(s) = self.0.get_mut(8..16) {
            s.copy_from_slice(&tree.to_be_bytes());
        }
    }

    /// Sets the type and clears the three words after it.
    fn set_type_and_clear(&mut self, ty: u32) {
        self.set_word(16, ty);
        if let Some(s) = self.0.get_mut(20..32) {
            s.fill(0);
        }
    }

    fn set_key_pair(&mut self, i: u32) {
        self.set_word(20, i);
    }

    fn key_pair(&self) -> u32 {
        self.word(20)
    }

    /// The chain address, or a tree's height.
    fn set_chain(&mut self, i: u32) {
        self.set_word(24, i);
    }

    /// The hash address, or a tree's index.
    fn set_hash(&mut self, i: u32) {
        self.set_word(28, i);
    }

    fn tree_index(&self) -> u32 {
        self.word(28)
    }

    /// `ADRSc` (FIPS 205 11.2): the layer's and type's last octets, the tree's last 8, and the
    /// three words.
    fn compressed(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        let parts: [&[u8]; 4] = [
            self.0.get(3..4).unwrap_or_default(),
            self.0.get(8..16).unwrap_or_default(),
            self.0.get(19..20).unwrap_or_default(),
            self.0.get(20..32).unwrap_or_default(),
        ];
        let mut rest = c.as_mut_slice();
        for p in parts {
            let (head, tail) = rest.split_at_mut(p.len().min(rest.len()));
            head.copy_from_slice(p.get(..head.len()).unwrap_or_default());
            rest = tail;
        }
        c
    }
}

/// SHAKE256's rate.
const RATE: usize = 136;

/// SHAKE256 of the parts' concatenation, `out.len()` octets.
fn shake256(keccak: Keccak, parts: &[&[u8]], out: &mut [u8]) {
    let mut state = [0u64; 25];
    let mut block = [0u8; RATE];
    let mut pos = 0usize;
    let absorb = |state: &mut [u64; 25], block: &[u8; RATE]| {
        let (lanes, _) = block.as_chunks::<8>();
        for (s, l) in state.iter_mut().zip(lanes) {
            *s ^= u64::from_le_bytes(*l);
        }
        keccak.with_f1600(|f| f(state));
    };
    for part in parts {
        let mut data = *part;
        while !data.is_empty() {
            let room = RATE.saturating_sub(pos);
            let (now, later) = data.split_at(room.min(data.len()));
            if let Some(dst) = block.get_mut(pos..pos.saturating_add(now.len())) {
                dst.copy_from_slice(now);
            }
            pos = pos.saturating_add(now.len());
            data = later;
            if pos == RATE {
                absorb(&mut state, &block);
                pos = 0;
            }
        }
    }
    if let Some(rest) = block.get_mut(pos..) {
        rest.fill(0);
    }
    if let Some(b) = block.get_mut(pos) {
        *b ^= 0x1f;
    }
    if let Some(b) = block.last_mut() {
        *b ^= 0x80;
    }
    absorb(&mut state, &block);
    block.zeroize();
    let mut chunks = out.chunks_mut(RATE).peekable();
    while let Some(chunk) = chunks.next() {
        let mut bytes = [0u8; RATE];
        let (lanes, _) = bytes.as_chunks_mut::<8>();
        for (l, s) in lanes.iter_mut().zip(state.iter()) {
            *l = s.to_le_bytes();
        }
        chunk.copy_from_slice(bytes.get(..chunk.len()).unwrap_or_default());
        bytes.zeroize();
        if chunks.peek().is_some() {
            keccak.with_f1600(|f| f(&mut state));
        }
    }
    state.zeroize();
}

/// HMAC of the parts with a key shorter than the digest's block (`block` octets).
fn hmac<D: Digest>(block: usize, key: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut pad = Zeroizing::new(vec![0u8; block]);
    for (p, k) in pad.iter_mut().zip(key) {
        *p = *k;
    }
    for p in pad.iter_mut() {
        *p ^= 0x36;
    }
    let mut inner = D::new();
    inner.update(pad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let inner = Zeroizing::new(inner.finalize().to_vec());
    for p in pad.iter_mut() {
        *p ^= 0x36 ^ 0x5c;
    }
    let mut outer = D::new();
    outer.update(pad.as_slice());
    outer.update(inner.as_slice());
    Zeroizing::new(outer.finalize().to_vec())
}

/// `MGF1` with the digest `D`, `len` octets.
fn mgf1<D: Digest>(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.saturating_add(64));
    let mut counter = 0u32;
    while out.len() < len {
        let mut d = D::new();
        d.update(seed);
        d.update(counter.to_be_bytes());
        out.extend_from_slice(&d.finalize());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// The first `n` octets of the digest of `start`'s state then the parts, into `out`.
fn finish<D: Digest + Clone>(start: &D, parts: &[&[u8]], out: &mut Node, n: usize) {
    let mut d = start.clone();
    for p in parts {
        d.update(p);
    }
    let mut digest = d.finalize();
    for (o, b) in out.iter_mut().zip(digest.iter().take(n)) {
        *o = *b;
    }
    digest.zeroize();
}

/// The SHA-2 digest of categories 3 and 5's `H`, `T`, `H_msg`, and `PRF_msg` (SHA-256 in
/// category 1), after `PK.seed` and its padding.
#[derive(Clone)]
enum Big {
    Sha256(Sha256),
    Sha512(Sha512),
}

/// The tweakable hashes' family, ready for a public seed.
#[derive(Clone)]
enum Hash {
    Shake(Keccak),
    Sha2(Box<Sha2>),
}

/// The SHA-2 states after `PK.seed` and its padding: `F` and `PRF`'s SHA-256, and the big
/// digest.
#[derive(Clone)]
struct Sha2 {
    small: Sha256,
    big: Big,
}

/// A key's hashing context: the parameters, `PK.seed`, and the hashes.
struct Ctx {
    p: &'static Params,
    pk_seed: Node,
    hash: Hash,
}

impl Ctx {
    fn new(variant: Variant, pk_seed: &[u8]) -> Self {
        let p = variant.params();
        let mut seed = [0u8; MAX_N];
        for (s, b) in seed.iter_mut().zip(pk_seed.iter().take(p.n)) {
            *s = *b;
        }
        let hash = if p.shake {
            Hash::Shake(Keccak::new())
        } else {
            let zeros = [0u8; 128];
            let padded = |block: usize| {
                let pad = zeros.get(..block.saturating_sub(p.n)).unwrap_or_default();
                (prefix(&seed, p.n), pad)
            };
            let mut small = Sha256::new();
            let (s, z) = padded(64);
            small.update(s);
            small.update(z);
            let big = if p.category == 1 {
                Big::Sha256(small.clone())
            } else {
                let mut big = Sha512::new();
                let (s, z) = padded(128);
                big.update(s);
                big.update(z);
                Big::Sha512(big)
            };
            Hash::Sha2(Box::new(Sha2 { small, big }))
        };
        Self {
            p,
            pk_seed: seed,
            hash,
        }
    }

    fn n(&self) -> usize {
        self.p.n
    }

    fn seed(&self) -> &[u8] {
        prefix(&self.pk_seed, self.p.n)
    }

    /// A tweakable hash of `m1 || m2` at `adrs`: `F` and `PRF` (`big` false) or `H` and `T`.
    fn tweak(&self, adrs: &Adrs, big: bool, m1: &[u8], m2: &[u8]) -> Node {
        let mut out = [0u8; MAX_N];
        let n = self.n();
        match &self.hash {
            Hash::Shake(k) => {
                let o = out.get_mut(..n).unwrap_or_default();
                shake256(*k, &[self.seed(), &adrs.0, m1, m2], o);
            }
            Hash::Sha2(sha2) => {
                let Sha2 { small, big: b } = &**sha2;
                let parts: [&[u8]; 3] = [&adrs.compressed(), m1, m2];
                match (big, b) {
                    (true, Big::Sha512(s)) => finish(s, &parts, &mut out, n),
                    (true, Big::Sha256(s)) => finish(s, &parts, &mut out, n),
                    (false, _) => finish(small, &parts, &mut out, n),
                }
            }
        }
        out
    }

    fn prf(&self, adrs: &Adrs, sk_seed: &[u8]) -> Zeroizing<Node> {
        Zeroizing::new(self.tweak(adrs, false, sk_seed, &[]))
    }

    fn f(&self, adrs: &Adrs, m: &[u8]) -> Node {
        self.tweak(adrs, false, m, &[])
    }

    fn h(&self, adrs: &Adrs, l: &Node, r: &Node) -> Node {
        let n = self.n();
        self.tweak(adrs, true, prefix(l, n), prefix(r, n))
    }

    fn t(&self, adrs: &Adrs, m: &[u8]) -> Node {
        self.tweak(adrs, true, m, &[])
    }

    /// `PRF_msg(SK.prf, opt_rand, M)`: the signature's randomizer `R`.
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Zeroizing<Node> {
        let mut out = Zeroizing::new([0u8; MAX_N]);
        let n = self.n();
        match &self.hash {
            Hash::Shake(k) => {
                let o = out.get_mut(..n).unwrap_or_default();
                shake256(*k, &[sk_prf, opt_rand, msg], o);
            }
            Hash::Sha2(sha2) => {
                let mac = match sha2.big {
                    Big::Sha256(_) => hmac::<Sha256>(64, sk_prf, &[opt_rand, msg]),
                    Big::Sha512(_) => hmac::<Sha512>(128, sk_prf, &[opt_rand, msg]),
                };
                for (o, d) in out.iter_mut().zip(mac.iter().take(n)) {
                    *o = *d;
                }
            }
        }
        out
    }

    /// `H_msg(R, PK.seed, PK.root, M)`: the message digest, `m` octets.
    fn h_msg(&self, r: &[u8], pk_root: &[u8], msg: &[u8]) -> [u8; MAX_M] {
        let mut out = [0u8; MAX_M];
        let m = self.p.m;
        let seed = self.seed();
        match &self.hash {
            Hash::Shake(k) => {
                let o = out.get_mut(..m).unwrap_or_default();
                shake256(*k, &[r, seed, pk_root, msg], o);
            }
            Hash::Sha2(sha2) => {
                let mut mgf_seed = Vec::with_capacity(128);
                mgf_seed.extend_from_slice(r);
                mgf_seed.extend_from_slice(seed);
                let digest = match sha2.big {
                    Big::Sha256(_) => {
                        let inner = Sha256::new()
                            .chain_update(r)
                            .chain_update(seed)
                            .chain_update(pk_root)
                            .chain_update(msg)
                            .finalize();
                        mgf_seed.extend_from_slice(&inner);
                        mgf1::<Sha256>(&mgf_seed, m)
                    }
                    Big::Sha512(_) => {
                        let inner = Sha512::new()
                            .chain_update(r)
                            .chain_update(seed)
                            .chain_update(pk_root)
                            .chain_update(msg)
                            .finalize();
                        mgf_seed.extend_from_slice(&inner);
                        mgf1::<Sha512>(&mgf_seed, m)
                    }
                };
                for (o, d) in out.iter_mut().zip(digest.iter()) {
                    *o = *d;
                }
            }
        }
        out
    }

    /// WOTS+'s `len`: `2n` message digits and 3 checksum digits.
    fn wots_len(&self) -> usize {
        self.n().saturating_mul(2).saturating_add(3)
    }

    /// `chain` (FIPS 205 Algorithm 5): `steps` steps of `F` from step `start`.
    fn chain(&self, x: &Node, start: u32, steps: u32, adrs: &mut Adrs) -> Node {
        let mut tmp = *x;
        for j in start..start.saturating_add(steps) {
            adrs.set_hash(j);
            tmp = self.f(adrs, prefix(&tmp, self.n()));
        }
        tmp
    }

    /// The message's and checksum's base-16 digits (FIPS 205 Algorithms 7 and 8).
    fn wots_digits(&self, msg: &[u8]) -> Vec<u32> {
        let len1 = self.n().saturating_mul(2);
        let mut digits = base_2b(msg, 4, len1);
        let csum = digits
            .iter()
            .fold(0u32, |acc, d| acc.wrapping_add(W_MAX.wrapping_sub(*d)));
        // Shifted left by (8 - (len2 * lg_w) % 8) % 8 = 4 bits, into 2 octets.
        let csum = csum.wrapping_shl(4).to_be_bytes();
        digits.extend(base_2b(csum.get(2..).unwrap_or_default(), 4, 3));
        digits
    }

    /// The WOTS+ private value `i` of the key pair at `adrs`.
    fn wots_sk(&self, sk_seed: &[u8], adrs: &Adrs, i: u32) -> Zeroizing<Node> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        sk_adrs.set_chain(i);
        self.prf(&sk_adrs, sk_seed)
    }

    /// `T_len` of the chains' ends, at the key pair's WOTS_PK address.
    fn wots_compress(&self, adrs: &Adrs, ends: &[u8]) -> Node {
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.t(&pk_adrs, ends)
    }

    /// `wots_pkGen` (FIPS 205 Algorithm 6).
    fn wots_pk_gen(&self, sk_seed: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.n();
        let mut ends = Vec::with_capacity(self.wots_len().saturating_mul(n));
        for i in 0..u32::try_from(self.wots_len()).unwrap_or(0) {
            let sk = self.wots_sk(sk_seed, adrs, i);
            adrs.set_chain(i);
            ends.extend_from_slice(prefix(&self.chain(&sk, 0, W_MAX, adrs), n));
        }
        self.wots_compress(adrs, &ends)
    }

    /// `wots_sign` (FIPS 205 Algorithm 7), appended to `out`.
    fn wots_sign(&self, msg: &[u8], sk_seed: &[u8], adrs: &mut Adrs, out: &mut Vec<u8>) {
        let n = self.n();
        for (i, d) in (0u32..).zip(self.wots_digits(msg)) {
            let sk = self.wots_sk(sk_seed, adrs, i);
            adrs.set_chain(i);
            out.extend_from_slice(prefix(&self.chain(&sk, 0, d, adrs), n));
        }
    }

    /// `wots_pkFromSig` (FIPS 205 Algorithm 8).
    fn wots_pk_from_sig(&self, sig: &[u8], msg: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.n();
        let mut ends = Vec::with_capacity(sig.len());
        for ((i, d), s) in (0u32..).zip(self.wots_digits(msg)).zip(sig.chunks(n)) {
            let mut x = [0u8; MAX_N];
            for (a, b) in x.iter_mut().zip(s) {
                *a = *b;
            }
            adrs.set_chain(i);
            ends.extend_from_slice(prefix(&self.chain(&x, d, W_MAX.wrapping_sub(d), adrs), n));
        }
        self.wots_compress(adrs, &ends)
    }

    /// `xmss_node` (FIPS 205 Algorithm 9): node `i` at height `z` of the XMSS tree at `adrs`.
    fn xmss_node(&self, sk_seed: &[u8], i: u32, z: u32, adrs: &mut Adrs) -> Node {
        if z == 0 {
            adrs.set_type_and_clear(WOTS_HASH);
            adrs.set_key_pair(i);
            return self.wots_pk_gen(sk_seed, adrs);
        }
        let l = self.xmss_node(sk_seed, i.wrapping_mul(2), z.wrapping_sub(1), adrs);
        let r = self.xmss_node(
            sk_seed,
            i.wrapping_mul(2).wrapping_add(1),
            z.wrapping_sub(1),
            adrs,
        );
        adrs.set_type_and_clear(TREE);
        adrs.set_chain(z);
        adrs.set_hash(i);
        self.h(adrs, &l, &r)
    }

    /// `xmss_sign` (FIPS 205 Algorithm 10) of an `n`-octet message, appended to `out`.
    fn xmss_sign(&self, msg: &[u8], sk_seed: &[u8], idx: u32, adrs: &mut Adrs, out: &mut Vec<u8>) {
        let n = self.n();
        let mut auth = Vec::with_capacity(n.saturating_mul(16));
        for j in 0..self.p.hp {
            let k = idx.wrapping_shr(j) ^ 1;
            auth.extend_from_slice(prefix(&self.xmss_node(sk_seed, k, j, adrs), n));
        }
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(idx);
        self.wots_sign(msg, sk_seed, adrs, out);
        out.extend_from_slice(&auth);
    }

    /// `xmss_pkFromSig` (FIPS 205 Algorithm 11).
    fn xmss_pk_from_sig(&self, idx: u32, sig: &[u8], msg: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.n();
        let (wots, auth) = sig.split_at(self.wots_len().saturating_mul(n).min(sig.len()));
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(idx);
        let mut node = self.wots_pk_from_sig(wots, msg, adrs);
        adrs.set_type_and_clear(TREE);
        adrs.set_hash(idx);
        for (k, a) in (0..self.p.hp).zip(auth.chunks(n)) {
            node = self.climb(&node, a, idx.wrapping_shr(k), k.wrapping_add(1), adrs);
        }
        node
    }

    /// One step up a tree: the parent of `node` (at index `at` of its level) and its sibling
    /// `auth`, at `height`.
    fn climb(&self, node: &Node, auth: &[u8], at: u32, height: u32, adrs: &mut Adrs) -> Node {
        let mut sibling = [0u8; MAX_N];
        for (s, a) in sibling.iter_mut().zip(auth) {
            *s = *a;
        }
        adrs.set_chain(height);
        let index = adrs.tree_index();
        if at & 1 == 0 {
            adrs.set_hash(index.wrapping_shr(1));
            self.h(adrs, node, &sibling)
        } else {
            adrs.set_hash(index.wrapping_sub(1).wrapping_shr(1));
            self.h(adrs, &sibling, node)
        }
    }

    /// The length of an XMSS signature: `(len + h') * n`.
    fn xmss_sig_len(&self) -> usize {
        let hp = usize::try_from(self.p.hp).unwrap_or(0);
        self.wots_len().saturating_add(hp).saturating_mul(self.n())
    }

    /// `ht_sign` (FIPS 205 Algorithm 12), appended to `out`.
    fn ht_sign(&self, msg: &Node, sk_seed: &[u8], tree: u64, leaf: u32, out: &mut Vec<u8>) {
        let n = self.n();
        let mut adrs = Adrs::default();
        let (mut tree, mut leaf) = (tree, leaf);
        let mut root = *msg;
        for j in 0..self.p.d {
            if j > 0 {
                leaf = u32::try_from(tree & mask(self.p.hp)).unwrap_or(0);
                tree = tree.wrapping_shr(self.p.hp);
            }
            adrs.set_layer(j);
            adrs.set_tree(tree);
            let start = out.len();
            self.xmss_sign(prefix(&root, n), sk_seed, leaf, &mut adrs, out);
            if j.wrapping_add(1) < self.p.d {
                let sig = out.get(start..).unwrap_or_default();
                root = self.xmss_pk_from_sig(leaf, sig, prefix(&root, n), &mut adrs);
            }
        }
    }

    /// `ht_verify` (FIPS 205 Algorithm 13).
    fn ht_verify(&self, msg: &Node, sig: &[u8], tree: u64, leaf: u32, pk_root: &[u8]) -> bool {
        let n = self.n();
        let mut adrs = Adrs::default();
        let (mut tree, mut leaf) = (tree, leaf);
        let mut node = *msg;
        let mut sigs = sig.chunks(self.xmss_sig_len());
        for j in 0..self.p.d {
            if j > 0 {
                leaf = u32::try_from(tree & mask(self.p.hp)).unwrap_or(0);
                tree = tree.wrapping_shr(self.p.hp);
            }
            adrs.set_layer(j);
            adrs.set_tree(tree);
            let Some(s) = sigs.next() else { return false };
            node = self.xmss_pk_from_sig(leaf, s, prefix(&node, n), &mut adrs);
        }
        sigs.next().is_none() && prefix(&node, n) == pk_root
    }

    /// `fors_skGen` (FIPS 205 Algorithm 14).
    fn fors_sk(&self, sk_seed: &[u8], adrs: &Adrs, idx: u32) -> Zeroizing<Node> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        sk_adrs.set_hash(idx);
        self.prf(&sk_adrs, sk_seed)
    }

    /// `fors_node` (FIPS 205 Algorithm 15).
    fn fors_node(&self, sk_seed: &[u8], i: u32, z: u32, adrs: &mut Adrs) -> Node {
        if z == 0 {
            let sk = self.fors_sk(sk_seed, adrs, i);
            adrs.set_chain(0);
            adrs.set_hash(i);
            return self.f(adrs, prefix(sk.as_slice(), self.n()));
        }
        let l = self.fors_node(sk_seed, i.wrapping_mul(2), z.wrapping_sub(1), adrs);
        let r = self.fors_node(
            sk_seed,
            i.wrapping_mul(2).wrapping_add(1),
            z.wrapping_sub(1),
            adrs,
        );
        adrs.set_chain(z);
        adrs.set_hash(i);
        self.h(adrs, &l, &r)
    }

    /// `fors_sign` (FIPS 205 Algorithm 16), appended to `out`.
    fn fors_sign(&self, md: &[u8], sk_seed: &[u8], adrs: &mut Adrs, out: &mut Vec<u8>) {
        let n = self.n();
        let (a, k) = (self.p.a, self.p.k);
        let indices = base_2b(md, a, usize::try_from(k).unwrap_or(0));
        for (i, idx) in (0u32..).zip(indices) {
            let base = i.wrapping_shl(a);
            let sk = self.fors_sk(sk_seed, adrs, base.wrapping_add(idx));
            out.extend_from_slice(prefix(sk.as_slice(), n));
            for j in 0..a {
                let s = idx.wrapping_shr(j) ^ 1;
                let node = i.wrapping_shl(a.wrapping_sub(j)).wrapping_add(s);
                out.extend_from_slice(prefix(&self.fors_node(sk_seed, node, j, adrs), n));
            }
        }
    }

    /// `fors_pkFromSig` (FIPS 205 Algorithm 17).
    fn fors_pk_from_sig(&self, sig: &[u8], md: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.n();
        let (a, k) = (self.p.a, self.p.k);
        let tree_len = usize::try_from(a)
            .unwrap_or(0)
            .saturating_add(1)
            .saturating_mul(n);
        let indices = base_2b(md, a, usize::try_from(k).unwrap_or(0));
        let mut roots = Vec::with_capacity(n.saturating_mul(64));
        for ((i, idx), tree) in (0u32..).zip(indices).zip(sig.chunks(tree_len)) {
            let (sk, auth) = tree.split_at(n.min(tree.len()));
            adrs.set_chain(0);
            adrs.set_hash(i.wrapping_shl(a).wrapping_add(idx));
            let mut node = self.f(adrs, sk);
            for (j, s) in (0..a).zip(auth.chunks(n)) {
                node = self.climb(&node, s, idx.wrapping_shr(j), j.wrapping_add(1), adrs);
            }
            roots.extend_from_slice(prefix(&node, n));
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(FORS_ROOTS);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.t(&pk_adrs, &roots)
    }

    /// The FORS signature's length: `k * (a + 1) * n`.
    fn fors_sig_len(&self) -> usize {
        let a = usize::try_from(self.p.a).unwrap_or(0);
        let k = usize::try_from(self.p.k).unwrap_or(0);
        k.saturating_mul(a.saturating_add(1))
            .saturating_mul(self.n())
    }

    /// The message digest's parts: `md` (`ceil(k * a / 8)` octets), and the tree and leaf
    /// indices.
    fn split_digest<'a>(&self, digest: &'a [u8]) -> (&'a [u8], u64, u32) {
        let p = self.p;
        let md_len = usize::try_from(p.k.wrapping_mul(p.a).wrapping_add(7) / 8).unwrap_or(0);
        let tree_bits = p.h.wrapping_sub(p.hp);
        let tree_len = usize::try_from(tree_bits.wrapping_add(7) / 8).unwrap_or(0);
        let leaf_len = usize::try_from(p.hp.wrapping_add(7) / 8).unwrap_or(0);
        let (md, rest) = digest.split_at(md_len.min(digest.len()));
        let (tree, rest) = rest.split_at(tree_len.min(rest.len()));
        let leaf = rest.get(..leaf_len).unwrap_or_default();
        let tree = to_int(tree) & mask(tree_bits);
        let leaf = u32::try_from(to_int(leaf) & mask(p.hp)).unwrap_or(0);
        (md, tree, leaf)
    }
}

/// An SLH-DSA public key: `PK.seed || PK.root`.
#[derive(Clone)]
pub struct PublicKey {
    variant: Variant,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// The public key in its encoding (`2n` octets), taken as given.
    pub fn from_bytes(variant: Variant, pk: &[u8]) -> Option<Self> {
        (pk.len() == variant.public_key_bytes()).then(|| Self {
            variant,
            bytes: pk.to_vec(),
        })
    }

    /// Its parameter set.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Its encoding.
    pub fn encoding(&self) -> &[u8] {
        &self.bytes
    }

    /// `slh_verify_internal` (FIPS 205 Algorithm 20): whether `sig` signs the message (as
    /// encoded by the caller).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let ctx = Ctx::new(self.variant, &self.bytes);
        let p = ctx.p;
        let n = p.n;
        if sig.len() != p.sig_len {
            return false;
        }
        let pk_root = self.bytes.get(n..).unwrap_or_default();
        let (r, rest) = sig.split_at(n);
        let (sig_fors, sig_ht) = rest.split_at(ctx.fors_sig_len().min(rest.len()));
        let digest = ctx.h_msg(r, pk_root, msg);
        let (md, tree, leaf) = ctx.split_digest(prefix(&digest, p.m));
        let mut adrs = Adrs::default();
        adrs.set_tree(tree);
        adrs.set_type_and_clear(FORS_TREE);
        adrs.set_key_pair(leaf);
        let pk_fors = ctx.fors_pk_from_sig(sig_fors, md, &mut adrs);
        ctx.ht_verify(&pk_fors, sig_ht, tree, leaf, pk_root)
    }
}

/// An SLH-DSA private key: `SK.seed || SK.prf || PK.seed || PK.root`.
#[derive(Clone)]
pub struct PrivateKey {
    variant: Variant,
    bytes: Zeroizing<Vec<u8>>,
}

impl PrivateKey {
    /// `slh_keygen_internal` (FIPS 205 Algorithm 18) from `SK.seed || SK.prf || PK.seed` (`3n`
    /// octets): the key with its root computed.
    pub fn generate(variant: Variant, seeds: &[u8]) -> Option<Self> {
        let n = variant.n();
        if seeds.len() != n.saturating_mul(3) {
            return None;
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(n.saturating_mul(4)));
        bytes.extend_from_slice(seeds);
        let root = Self::root(variant, &bytes);
        bytes.extend_from_slice(prefix(&root, n));
        Some(Self { variant, bytes })
    }

    /// The root of the top XMSS tree of the key's seeds.
    fn root(variant: Variant, bytes: &[u8]) -> Node {
        let n = variant.n();
        let ctx = Ctx::new(
            variant,
            bytes.get(n.saturating_mul(2)..).unwrap_or_default(),
        );
        let mut adrs = Adrs::default();
        adrs.set_layer(ctx.p.d.wrapping_sub(1));
        ctx.xmss_node(prefix(bytes, n), 0, ctx.p.hp, &mut adrs)
    }

    /// The private key in its encoding (`4n` octets), taken as given.
    pub fn from_bytes(variant: Variant, sk: &[u8]) -> Option<Self> {
        (sk.len() == variant.private_key_bytes()).then(|| Self {
            variant,
            bytes: Zeroizing::new(sk.to_vec()),
        })
    }

    /// Its parameter set.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Its encoding.
    pub fn encoding(&self) -> &[u8] {
        &self.bytes
    }

    /// Its public key.
    pub fn public(&self) -> PublicKey {
        PublicKey {
            variant: self.variant,
            bytes: self
                .bytes
                .get(self.variant.n().saturating_mul(2)..)
                .unwrap_or_default()
                .to_vec(),
        }
    }

    /// Whether the seeds make the key's `PK.root` (`ossl_slh_dsa_key_pairwise_check`).
    pub fn pairwise(&self) -> bool {
        let n = self.variant.n();
        let root = Self::root(self.variant, &self.bytes);
        Some(prefix(&root, n)) == self.bytes.get(n.saturating_mul(3)..)
    }

    /// `slh_sign_internal` (FIPS 205 Algorithm 19) of the message (as encoded by the caller),
    /// with `n` octets of additional randomness, or `PK.seed` (deterministic) when `None`; `None`
    /// for randomness of another length.
    pub fn sign(&self, msg: &[u8], add_rand: Option<&[u8]>) -> Option<Vec<u8>> {
        let n = self.variant.n();
        let (sk, pk) = self
            .bytes
            .split_at(n.saturating_mul(2).min(self.bytes.len()));
        let (sk_seed, sk_prf) = sk.split_at(n.min(sk.len()));
        let (pk_seed, pk_root) = pk.split_at(n.min(pk.len()));
        let opt_rand = add_rand.unwrap_or(pk_seed);
        if opt_rand.len() != n {
            return None;
        }
        let ctx = Ctx::new(self.variant, pk_seed);
        let mut sig = Vec::with_capacity(ctx.p.sig_len);
        let r = ctx.prf_msg(sk_prf, opt_rand, msg);
        sig.extend_from_slice(prefix(&*r, n));
        let mut digest = ctx.h_msg(prefix(&*r, n), pk_root, msg);
        let (md, tree, leaf) = ctx.split_digest(prefix(&digest, ctx.p.m));
        let mut adrs = Adrs::default();
        adrs.set_tree(tree);
        adrs.set_type_and_clear(FORS_TREE);
        adrs.set_key_pair(leaf);
        let start = sig.len();
        ctx.fors_sign(md, sk_seed, &mut adrs, &mut sig);
        let pk_fors = ctx.fors_pk_from_sig(sig.get(start..).unwrap_or_default(), md, &mut adrs);
        digest.zeroize();
        ctx.ht_sign(&pk_fors, sk_seed, tree, leaf, &mut sig);
        (sig.len() == ctx.p.sig_len).then_some(sig)
    }
}

/// The message as FIPS 205's pure signing covers it, `0 || |ctx| || ctx || M`, or `None` for a
/// context over 255 octets.
pub fn encode_message(context: &[u8], message: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let n = u8::try_from(context.len()).ok()?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        context
            .len()
            .saturating_add(message.len())
            .saturating_add(2),
    ));
    out.extend_from_slice(&[0, n]);
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    Some(out)
}

#[cfg(test)]
#[expect(clippy::arithmetic_side_effects, reason = "sizes in tests")]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sha256(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    /// The reference's roots and signatures (SHA-256) of the key from seeds 0, 1, 2, ...: of
    /// `abc` deterministic and pure, deterministic and raw, and with randomness `a0 a1 ...`
    /// and the context `01 02 03`.
    const KATS: [(Variant, &str, [&str; 3]); 12] = [
        (
            Variant::Sha2_128s,
            "990ce6298792b128846a8e4a3a68954c",
            [
                "2298d75c43b71cecf2477f10c7965c9be945e9b79b7edfa988b4ba71d4135bae",
                "53352a32795d03b5b9383ac372bf24007d88de093df4f1f76fddf6b33c74ff98",
                "8dffe57efad6e891bb039a14673076a4722a562e7dd8fd4274bd279edf07cc53",
            ],
        ),
        (
            Variant::Sha2_128f,
            "3b56e816847f000386aeec2e2bb9e1b5",
            [
                "7c4622720e758897ec5f2089049bb5e5d98fc2e88bfdacf4fad3a1e20f80d5f8",
                "9ef9f988a1b538b48b94aa31167f65992d3811361d67b57572c33ca643dd5beb",
                "83ff223f7649a4b0fcc6826de6d546c4e8b138e0a87ad5e0addb2ae2eeabd217",
            ],
        ),
        (
            Variant::Sha2_192s,
            "b6f282ce116ff59bce2d9fc4a67c6031dabdce326c34f541",
            [
                "ed4857e6246ed2e015427b311d425bec6f717d0d0903e772bcb3e398e4be51e7",
                "df69937f2b450557c1d37c95bf9b7a4792ce16b704792e132f0d749785c9d721",
                "a72f8b4c7cc2c63dfe8616b3ec6bb96247d7848e735ce5c98e1d4ca580c2402c",
            ],
        ),
        (
            Variant::Sha2_192f,
            "9236ccebbb3a90ac2452dd89de49dab1340ec02419a2870e",
            [
                "61e8fbd5d63729609c76ddba9786673995d71846fefd93e4221fe620ed0d0574",
                "950a164f569924bf950508f3495b8ccf8882b7661b9aa1a17d2fcc2cc55f0e27",
                "a5e25fc44af8d97057a2ed0d019dec44210c906cb0baeac33c9d0f657cf7465c",
            ],
        ),
        (
            Variant::Sha2_256s,
            "da7163e601352515bc0f06f9f4f44be71a5a65ee9dca5575cf4a7b6d4a87d6e2",
            [
                "92b7bc7df0425035d8c9898130da846d34af62dae85d017461d26118c5bd5665",
                "26eb9662f795b3c91e1145a11d28a9c72e7be5b53add0856deb7166457b5adb3",
                "3fb41b3173ccbf010a9d93ba9a1cd2cde37c103701dac7c9883786257545bea5",
            ],
        ),
        (
            Variant::Sha2_256f,
            "42cffe64ddbd6731063752684df77c8b58c225dc6b491208916b654ea1393176",
            [
                "95af7cab7991d80101be2e55871758d9e7cf68849be2989ba21b1f313a3be46b",
                "943e42c39fa825c5510516566bd7735616c07e643cd7b768349ef6f7178a890f",
                "4f5d31c60d15feb4b653ebec23ec1a5ca4bc58b7783661b97366f3c465435ae5",
            ],
        ),
        (
            Variant::Shake128s,
            "89fd81fdbb5b94129b14761bdc6bf682",
            [
                "40cb225858deb428310c9b00257031bf5852cee5228db53a9d3a696861775f84",
                "047674bee3ebbf7204f54ed88e45dcda24e9021bf85bb522791b06ec42c536bb",
                "14474bc85e24b79563ebf81a7a03d191af74ffbf001b3d681a1ccb1db08e2d62",
            ],
        ),
        (
            Variant::Shake128f,
            "a90e4715b9a925c332801767fd786371",
            [
                "bb095008ae794ef660c4189f9fef4ec0613c61646b426d550200949cd8e3d8a5",
                "94fc3054816e9f5b77c1d5b49110e26116869a82bc873c5edd4ec0fed1354d53",
                "f944bdcd211e3b9654d4ea711b42696913e635fd3142857768f5131bcdab237c",
            ],
        ),
        (
            Variant::Shake192s,
            "eb247f955d8eca24a5860536c56b2c4d1e8d8e835eb27d2d",
            [
                "cfe3a23272bb5f00d3fd1061e399fc3fe0c28679dc2777f71be642253f94b79f",
                "3563bedfa0ff65cc8790178a920d1b0c2f14ca4a0b58a3e617d86516ae7ebd33",
                "a1f85fa3460e7db43a5a575c21f147c9cf205c85b1caccdd8d214a0f2bc674d8",
            ],
        ),
        (
            Variant::Shake192f,
            "3f01b06bebed020a459696868d115fe8507ded8dc08e825d",
            [
                "34143317940905bf9a1f9d30fde47707f0c2b85a8aa01c5dfcf5ec28d716e294",
                "ac828b1b14d709b713bda52535ea80648e809cab3102204730fb4d7fcb1ea438",
                "8a5a0723a33270eb63c0229af13d570b033acdd0c179c650ebeeaa2fdbb518be",
            ],
        ),
        (
            Variant::Shake256s,
            "27ea444dbc8ca9c169fd484b9e977eb77a4f233550757e025cf180ede7e8839f",
            [
                "27c73d485fef098216b07d261f7ec0f7de0138d5315f57a46757bb6484e9e5c3",
                "3ff2e9c59306aa4a8d3cfb120112d20b4ea5dd925c005cc68a8e560eecd343b1",
                "cb0908b25cee4fbbdea16466a3028f7107b5382fae0b46f83da86a47ca29ada0",
            ],
        ),
        (
            Variant::Shake256f,
            "818d7e76beef979b5bbf9161fdefa21bd0fe0bfe19157a5711a8de8a8f6878e6",
            [
                "ec4d1f66beaeae970f8401b275129cc276136bdd6be6944d5bb9e318eb55b935",
                "0b73062168a21664d0f7fd054f57316cddbcb9c60aa9a713f002e50269622418",
                "a3f30797b782b4c0c651e5831a9e5e5b3af94e47814fca59d47a48cdc264fa80",
            ],
        ),
    ];

    /// The seeds `0, 1, 2, ...` of a key.
    fn seeds(v: Variant) -> Vec<u8> {
        (0..v.n() * 3).map(|i| u8::try_from(i).unwrap()).collect()
    }

    /// Checks a parameter set's root and signatures against the reference's.
    fn check_kat(v: Variant) {
        let (_, root, sigs) = KATS.iter().find(|k| k.0 == v).unwrap();
        let key = PrivateKey::generate(v, &seeds(v)).unwrap();
        assert_eq!(hex(&key.encoding()[v.n() * 3..]), *root, "{v:?} root");
        assert!(key.pairwise());
        let pure = encode_message(&[], b"abc").unwrap();
        let ctx = encode_message(&[1, 2, 3], b"abc").unwrap();
        let rand: Vec<u8> = (0..v.n())
            .map(|i| 0xa0 + u8::try_from(i).unwrap())
            .collect();
        let cases: [(&[u8], Option<&[u8]>); 3] =
            [(&pure, None), (b"abc", None), (&ctx, Some(&rand))];
        let public = key.public();
        for ((msg, rand), want) in cases.into_iter().zip(sigs) {
            let sig = key.sign(msg, rand).unwrap();
            assert_eq!(sig.len(), v.signature_bytes());
            assert_eq!(sha256(&sig), *want, "{v:?} signature");
            assert!(public.verify(msg, &sig));
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(base_2b(&[0x12, 0x34], 4, 4), [1, 2, 3, 4]);
        assert_eq!(base_2b(&[0xff, 0xc0], 6, 2), [63, 60]);
        assert_eq!(base_2b(&[0b1010_1100, 0b0101_0000], 12, 1), [0xac5]);
        assert_eq!(to_int(&[1, 2]), 0x102);
        assert_eq!(mask(64), u64::MAX);
        assert_eq!(mask(9), 0x1ff);
        let mut a = Adrs::default();
        a.set_layer(0x0102_0304);
        a.set_tree(0x1112_1314_1516_1718);
        a.set_type_and_clear(3);
        a.set_key_pair(0x2122_2324);
        a.set_chain(0x3132_3334);
        a.set_hash(0x4142_4344);
        assert_eq!(
            hex(&a.compressed()),
            "04111213141516171803212223243132333441424344"
        );
        a.set_type_and_clear(2);
        assert_eq!(a.key_pair(), 0);
        assert_eq!(a.tree_index(), 0);
    }

    #[test]
    fn sizes() {
        for v in Variant::ALL {
            let p = v.params();
            let (n, h, d, a, k) = (p.n, p.h as usize, p.d as usize, p.a as usize, p.k as usize);
            let len = 2 * n + 3;
            assert_eq!(p.hp as usize * d, h, "{v:?}");
            assert_eq!(n + k * (a + 1) * n + (h + d * len) * n, p.sig_len, "{v:?}");
            assert_eq!(v.public_key_bytes(), 2 * n);
            assert_eq!(v.private_key_bytes(), 4 * n);
        }
    }

    #[test]
    fn known_answers() {
        // The fast parameter sets of 128 bits; the others are slow without optimization, so
        // `all_known_answers` checks them (`cargo test --release -- --ignored`).
        check_kat(Variant::Sha2_128f);
        check_kat(Variant::Shake128f);
    }

    #[test]
    #[ignore = "slow without optimization"]
    fn all_known_answers() {
        for v in Variant::ALL {
            check_kat(v);
        }
    }

    #[test]
    fn verification() {
        for v in [Variant::Sha2_128f, Variant::Shake128f] {
            let key = PrivateKey::generate(v, &seeds(v)).unwrap();
            let public = PublicKey::from_bytes(v, key.public().encoding()).unwrap();
            let sig = key.sign(b"message", None).unwrap();
            assert!(public.verify(b"message", &sig));
            assert!(!public.verify(b"messagf", &sig));
            assert!(!public.verify(b"message", &sig[1..]));
            let mut longer = sig.clone();
            longer.push(0);
            assert!(!public.verify(b"message", &longer));
            for at in [0, 20, v.n() + 5, sig.len() / 2, sig.len() - 1] {
                let mut bad = sig.clone();
                bad[at] ^= 1;
                assert!(!public.verify(b"message", &bad), "{v:?} at {at}");
            }
            // Randomness of another length, keys of other lengths, and a changed root.
            assert!(key.sign(b"m", Some(&[0; 15])).is_none());
            assert!(PrivateKey::from_bytes(v, &[0; 63]).is_none());
            assert!(PublicKey::from_bytes(v, &[0; 33]).is_none());
            assert!(PrivateKey::generate(v, &[0; 47]).is_none());
            let mut sk = key.encoding().to_vec();
            sk[63] ^= 1;
            let changed = PrivateKey::from_bytes(v, &sk).unwrap();
            assert!(!changed.pairwise());
            assert!(!changed.public().verify(b"message", &sig));
        }
        assert!(encode_message(&[0; 256], b"").is_none());
        assert_eq!(
            &*encode_message(&[7], b"ab").unwrap(),
            &[0, 1, 7, b'a', b'b']
        );
    }
}
