//! The group, signature algorithm, and certificate type lists of a context or connection
//! (`t1_lib.c`'s `tls1_set_groups_list`, `tls1_set_groups`, `tls1_set_sigalgs_list`,
//! `tls1_set_sigalgs`, `tls1_get0_implemented_groups`; `ssl_lib.c`'s certificate types), which
//! `io::config` hands to the core.
//!
//! Groups are named from the context's providers (`ctx->group_list`, made once per context
//! here); signature algorithms from its table (`ctx->sigalg_lookup_cache`, the core's
//! [`Cache`]). The configured signature algorithms live in the [`Cert`](super::cert::Cert), as
//! OpenSSL's do.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::Arc;

use rustyssl_abi::{
    CONF_R_LIST_CANNOT_BE_NULL, EC_KEY, ERR_LIB_CONF, ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, NID_ED448, NID_ED25519, NID_X9_62_id_ecPublicKey, NID_dsa,
    NID_id_GostR3410_2001, NID_id_GostR3410_2012_256, NID_id_GostR3410_2012_512, NID_md5_sha1,
    NID_rsaEncryption, NID_rsassaPss, NID_undef, OPENSSL_STACK, OSSL_LIB_CTX, SSL,
    SSL_CTRL_GET_GROUPS, SSL_CTRL_GET_SHARED_GROUP, SSL_CTRL_GET0_IMPLEMENTED_GROUPS,
    SSL_CTRL_SET_CLIENT_SIGALGS, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, SSL_CTRL_SET_GROUPS,
    SSL_CTRL_SET_GROUPS_LIST, SSL_CTRL_SET_SIGALGS, SSL_CTRL_SET_SIGALGS_LIST,
    SSL_CTRL_SET_TMP_ECDH, SSL_CTX, SSL_R_BAD_LENGTH, SSL_R_MISSING_PARAMETERS,
    SSL_R_UNSUPPORTED_CONFIG_VALUE, TLSEXT_cert_type_rpk, TLSEXT_cert_type_x509,
    stack_st_SSL_CIPHER,
};
use rustyssl_tls::conn::Connection;
use rustyssl_tls::conn::common::groups::{group_to_nid, nid_to_group};
use rustyssl_tls::conn::common::sigalgs::{
    Cache, PKEY_GOST01, PKEY_GOST12_256, PKEY_GOST12_512, Sig, SigAlg,
};
use rustyssl_tls::crypto::{GroupInfo, Provider};

use super::cert::Cert;
use super::conn::{Ssl, ctx_of, ssl};
use super::ctx::{Ctx, ctx};
use super::tls_provider::EvpProvider;
use crate::conf::c_dup;
use crate::ec::group::EC_GROUP_get_curve_name;
use crate::ec::key::EC_KEY_get0_group;
use crate::err::{self, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_type};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::ffi::ffi_export;
use crate::objects::{OBJ_ln2nid, OBJ_nid2ln, OBJ_sn2nid};
use crate::stack::OPENSSL_sk_push;

/// The most key shares a client list may ask for (`OPENSSL_CLIENT_MAX_KEY_SHARES`,
/// `ssl_local.h`).
const MAX_KEY_SHARES: usize = 4;
/// The longest group name, without its NUL (`GROUP_NAME_BUFFER_LENGTH` - 1).
const MAX_GROUP_NAME: usize = 63;
/// The longest signature algorithm element, without its NUL (`TLS_MAX_SIGSTRING_LEN` - 1).
const MAX_SIGSTRING: usize = 39;
/// The pseudo groups (`default_group_strings`: `DEFAULT`, `DEFAULT_SUITE_B`).
const DEFAULT_GROUPS: [(&[u8], &[u8]); 2] = [
    (
        b"DEFAULT",
        b"?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1 / ?ffdhe2048:?ffdhe3072",
    ),
    (b"DEFAULT_SUITE_B", b"?secp256r1:?secp384r1"),
];
/// The GOST names the providers' table doesn't resolve (`name2id_arr`).
const GOST_NAMES: [(&[u8], u16); 7] = [
    (b"GC256A", 0x22),
    (b"GC256B", 0x23),
    (b"GC256C", 0x24),
    (b"GC256D", 0x25),
    (b"GC512A", 0x26),
    (b"GC512B", 0x27),
    (b"GC512C", 0x28),
];

/// A context's or connection's groups (`ext.supportedgroups`, `ext.keyshares`, `ext.tuples`),
/// as OpenSSL stores them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct GroupLists {
    /// The groups, in preference order.
    pub(crate) groups: Vec<u16>,
    /// The groups to send key shares for; `[0]` for "the first usable one".
    pub(crate) keyshares: Vec<u16>,
    /// The number of groups in each preference tuple.
    pub(crate) tuples: Vec<usize>,
}

/// A group of the context's providers (one `TLS_GROUP_INFO` per name and alias).
#[derive(Debug)]
pub(crate) struct GroupEntry {
    /// The code point.
    pub(crate) id: u16,
    /// The TLS name (`tlsname`), at a stable address for the context's lifetime.
    pub(crate) tlsname: CString,
    /// The providers' algorithm name (`realname`).
    realname: String,
    /// The TLS versions it may be used with (`mintls`, `maxtls`).
    mintls: i32,
    /// See `mintls`.
    maxtls: i32,
}

/// The lists a context holds and a connection copies from it (`SSL_new`), with the DANE
/// settings (`super::dane`).
#[derive(Debug, Default)]
pub(crate) struct Lists {
    /// The configured groups, or `None` for the default list.
    pub(crate) groups: Option<GroupLists>,
    /// The certificate types (`client_cert_type`, `server_cert_type`), at stable addresses for
    /// the `get0` functions.
    pub(crate) client_cert_type: Option<Box<[u8]>>,
    /// See `client_cert_type`.
    pub(crate) server_cert_type: Option<Box<[u8]>>,
    /// The context's providers' groups (`group_list`), made on first use.
    pub(crate) implemented: Option<Arc<Vec<GroupEntry>>>,
    /// A context's DANE matching types (`ctx->dane`).
    pub(crate) dane_ctx: super::dane::DaneCtx,
    /// A connection's DANE state (`s->dane`), boxed for `SSL_get0_dane`.
    pub(crate) dane: Box<super::dane::Dane>,
}

impl Lists {
    /// A new connection's copy of its context's lists (`SSL_new`).
    pub(crate) fn for_ssl(&self) -> Self {
        Self {
            groups: self.groups.clone(),
            client_cert_type: self.client_cert_type.clone(),
            server_cert_type: self.server_cert_type.clone(),
            implemented: self.implemented.clone(),
            dane_ctx: super::dane::DaneCtx::default(),
            dane: super::dane::Dane::for_ssl(&self.dane_ctx),
        }
    }
}

impl GroupLists {
    /// What the core's configuration takes: the groups, the key share groups (empty for "the
    /// first usable one"), and where each tuple starts.
    pub(crate) fn for_core(&self) -> (Vec<u16>, Vec<u16>, Vec<usize>) {
        let shares = if self.keyshares == [0] {
            Vec::new()
        } else {
            self.keyshares.clone()
        };
        let mut starts = Vec::with_capacity(self.tuples.len());
        let mut at = 0usize;
        for &n in &self.tuples {
            starts.push(at);
            at = at.saturating_add(n);
        }
        (self.groups.clone(), shares, starts)
    }
}

/// `CONF_parse_list`: calls `cb` with each item of `list` split at `sep` (`None` for an empty
/// one), stopping at a result of 0 or less, which it returns; 1 after the last.
pub(crate) fn parse_list(
    list: &[u8],
    sep: u8,
    nospc: bool,
    cb: &mut dyn FnMut(Option<&[u8]>) -> c_int,
) -> c_int {
    for item in rustyssl_conf::list_items(list, sep, nospc) {
        let ret = cb(item);
        if ret <= 0 {
            return ret;
        }
    }
    1
}

/// The groups of the context's providers, made once (`ssl_load_groups`).
pub(crate) fn implemented(x: &Ctx) -> Arc<Vec<GroupEntry>> {
    if let Some(g) = &x.state().lists.implemented {
        return Arc::clone(g);
    }
    let propq = x.propq.as_ref().map_or(ptr::null(), |p| p.as_ptr());
    // SAFETY: the context's library context, which outlives it, and its property query. No
    // lock is held while the providers are asked.
    let prov = unsafe { EvpProvider::new(x.libctx, propq) };
    let entries = Arc::new(flatten(prov.groups()));
    let mut st = x.state();
    Arc::clone(st.lists.implemented.get_or_insert(entries))
}

/// One entry per name and alias, in the providers' order.
fn flatten(infos: Vec<GroupInfo>) -> Vec<GroupEntry> {
    let mut out = Vec::new();
    for g in infos {
        for name in core::iter::once(&g.name).chain(&g.aliases) {
            if let Ok(tlsname) = CString::new(name.as_bytes()) {
                out.push(GroupEntry {
                    id: g.id,
                    tlsname,
                    realname: g.internal_name.clone(),
                    mintls: g.min_tls,
                    maxtls: g.max_tls,
                });
            }
        }
    }
    out
}

/// `tls1_group_name2id`: a group's code point by its TLS or provider name (any case), or 0.
fn name2id(table: &[GroupEntry], name: &[u8]) -> u16 {
    table
        .iter()
        .find(|g| {
            g.tlsname.as_bytes().eq_ignore_ascii_case(name)
                || g.realname.as_bytes().eq_ignore_ascii_case(name)
        })
        .map_or(0, |g| g.id)
}

/// `gid_cb_st`: a group list being parsed.
struct GroupParse<'a> {
    table: &'a [GroupEntry],
    gids: Vec<u16>,
    /// Each tuple's count; the last is the tuple being filled.
    tuples: Vec<usize>,
    ksids: Vec<u16>,
    /// Whether a pseudo group is being expanded, and whether at its first tuple.
    inner: bool,
    first: bool,
}

impl GroupParse<'_> {
    /// `close_tuple`: starts a new tuple unless the current one is empty.
    fn close_tuple(&mut self) {
        if self.tuples.last().is_some_and(|&n| n != 0) {
            self.tuples.push(0);
        }
    }

    /// `tuple_cb`: one tuple of groups.
    fn tuple(&mut self, item: Option<&[u8]>) -> c_int {
        let Some(t) = item.filter(|t| !t.is_empty()) else {
            err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_CONFIG_VALUE, "tuple_cb");
            return 0;
        };
        if self.inner && !self.first {
            self.close_tuple();
        }
        self.first = false;
        let ret = parse_list(t, b':', true, &mut |e| self.gid(e));
        if !self.inner {
            self.close_tuple();
        }
        ret
    }

    /// `gid_cb`: one group with its prefixes: 1 to go on, 0 for an unknown group (without
    /// `?`), -1 for a syntax error.
    fn gid(&mut self, item: Option<&[u8]>) -> c_int {
        let Some(mut e) = item.filter(|e| !e.is_empty()) else {
            err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_CONFIG_VALUE, "gid_cb");
            return 0;
        };
        let (mut ignore_unknown, mut add_keyshare, mut remove) = (false, false, false);
        while let Some((&c0, rest)) = e.split_first() {
            let flag = match c0 {
                b'/' | b':' => return -1,
                b'*' => &mut add_keyshare,
                b'-' => &mut remove,
                b'?' => &mut ignore_unknown,
                b'D' | b'd' => {
                    if let Some(&(_, list)) = DEFAULT_GROUPS
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(e))
                    {
                        if ignore_unknown || remove {
                            return -1;
                        }
                        let mut s = Vec::with_capacity(list.len().saturating_add(1));
                        if add_keyshare && list.first() != Some(&b'*') {
                            s.push(b'*');
                        }
                        s.extend_from_slice(list);
                        let saved_first = self.first;
                        self.inner = true;
                        self.first = true;
                        let ret = parse_list(&s, b'/', true, &mut |t| self.tuple(t));
                        self.inner = false;
                        self.first = saved_first;
                        return ret;
                    }
                    break;
                }
                _ => break,
            };
            if *flag {
                return -1;
            }
            *flag = true;
            e = rest;
        }
        if e.is_empty() || e.len() > MAX_GROUP_NAME {
            return -1;
        }
        let mut gid = name2id(self.table, e);
        if gid == 0 {
            gid = GOST_NAMES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(e))
                .map_or(0, |&(_, id)| id);
        }
        if gid == 0 || !self.table.iter().any(|g| g.id == gid) {
            return c_int::from(ignore_unknown);
        }
        if remove {
            self.remove(gid);
        } else if !self.gids.contains(&gid) {
            self.gids.push(gid);
            if let Some(n) = self.tuples.last_mut() {
                *n = n.saturating_add(1);
            }
            if add_keyshare {
                self.ksids.push(gid);
            }
        }
        1
    }

    /// A `-` group: out of the list, its tuple's count, and the key shares, if there.
    fn remove(&mut self, gid: u16) {
        let Some(i) = self.gids.iter().position(|&g| g == gid) else {
            return;
        };
        self.gids.remove(i);
        let closed = self.tuples.len().saturating_sub(1);
        let mut target = closed;
        let mut k = 0usize;
        for (j, &n) in self.tuples.iter().take(closed).enumerate() {
            k = k.saturating_add(n);
            if k > i {
                target = j;
                break;
            }
        }
        if let Some(n) = self.tuples.get_mut(target) {
            *n = n.saturating_sub(1);
        }
        if let Some(p) = self.ksids.iter().position(|&g| g == gid) {
            self.ksids.remove(p);
        }
    }
}

/// `tls1_set_groups_list`: the lists for `s` (3.5's syntax: `/` between tuples, `:` between
/// groups, `*` for a key share, `?` to ignore an unknown group, `-` to remove one, and the
/// `DEFAULT` pseudo groups), or `None` (with OpenSSL's error, if it raises one).
pub(crate) fn groups_list(table: &[GroupEntry], s: &[u8]) -> Option<GroupLists> {
    let s = s.trim_ascii_start();
    let mut g = GroupParse {
        table,
        gids: Vec::new(),
        tuples: vec![0],
        ksids: Vec::new(),
        inner: false,
        first: false,
    };
    if s.is_empty() {
        return Some(GroupLists::default());
    }
    match parse_list(s, b'/', true, &mut |t| g.tuple(t)) {
        0 => return None,
        -1 => {
            let text = format!("Syntax error in '{}'", String::from_utf8_lossy(s));
            err::raise_with_text(
                ERR_LIB_SSL,
                ERR_R_PASSED_INVALID_ARGUMENT,
                "tls1_set_groups_list",
                &text,
            );
            return None;
        }
        _ => {}
    }
    g.tuples.pop();
    g.tuples.retain(|&n| n != 0);
    if g.ksids.len() > MAX_KEY_SHARES {
        let text = format!(
            "To many keyshares requested in '{}' (max = {MAX_KEY_SHARES})",
            String::from_utf8_lossy(s)
        );
        err::raise_with_text(
            ERR_LIB_SSL,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "tls1_set_groups_list",
            &text,
        );
        return None;
    }
    if !g.gids.is_empty() && g.ksids.is_empty() {
        g.ksids.push(0);
    }
    Some(GroupLists {
        groups: g.gids,
        keyshares: g.ksids,
        tuples: g.tuples,
    })
}

/// `tls1_set_groups`: the lists for legacy NIDs (no duplicates, every one known), or `None`.
pub(crate) fn groups_from_nids(nids: &[c_int]) -> Option<GroupLists> {
    if nids.is_empty() {
        err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, "tls1_set_groups");
        return None;
    }
    // Two bitmaps of 64 (`unsigned long`) as OpenSSL keeps: ids below 0x100, and the rest.
    let (mut ec, mut dh) = (0u64, 0u64);
    let mut groups = Vec::with_capacity(nids.len());
    for &nid in nids {
        let id = nid_to_group(nid);
        let bit = u32::from(id & 0xff);
        if bit >= 64 {
            return None;
        }
        let mask = 1u64 << bit;
        let seen = if id < 0x100 { &mut ec } else { &mut dh };
        if id == 0 || *seen & mask != 0 {
            return None;
        }
        *seen |= mask;
        groups.push(id);
    }
    let n = groups.len();
    Some(GroupLists {
        groups,
        keyshares: vec![0],
        tuples: vec![n],
    })
}

/// `ssl_set_tmp_ecdh_groups`: the lists for an `EC_KEY`'s named curve, or `None`.
///
/// # Safety
/// `key` is a live `EC_KEY`.
unsafe fn groups_from_ec_key(key: *const EC_KEY) -> Option<GroupLists> {
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(key) };
    if group.is_null() {
        err::raise(
            ERR_LIB_SSL,
            SSL_R_MISSING_PARAMETERS,
            "ssl_set_tmp_ecdh_groups",
        );
        return None;
    }
    // SAFETY: the key's group.
    let nid = unsafe { EC_GROUP_get_curve_name(group) };
    if nid == NID_undef {
        return None;
    }
    groups_from_nids(&[nid])
}

/// The signature type an algorithm checks against (`lu->sig`, an `EVP_PKEY_*`).
fn sig_type(lu: &SigAlg) -> c_int {
    match &lu.sig {
        Sig::Rsa => NID_rsaEncryption,
        Sig::RsaPss => NID_rsassaPss,
        Sig::Dsa => NID_dsa,
        Sig::Ec => NID_X9_62_id_ecPublicKey,
        Sig::Ed25519 => NID_ED25519,
        Sig::Ed448 => NID_ED448,
        Sig::Gost => match lu.sig_idx {
            PKEY_GOST01 => NID_id_GostR3410_2001,
            PKEY_GOST12_256 => NID_id_GostR3410_2012_256,
            PKEY_GOST12_512 => NID_id_GostR3410_2012_512,
            _ => NID_undef,
        },
        Sig::Other(_) => NID_undef,
    }
}

/// The signature algorithm table: the context's (`sigalg_lookup_cache`: built-in, then the
/// providers'), or with no context the built-in one (`sigalg_lookup_tbl`, for syntax checks).
/// The core's pseudo entry for TLS 1.1's MD5+SHA-1 isn't one of them.
fn sigalg_table(x: Option<&Ctx>) -> Vec<SigAlg> {
    let (libctx, propq) = match x {
        Some(x) => (
            x.libctx,
            x.propq.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
        ),
        None => (ptr::null_mut(), ptr::null()),
    };
    // SAFETY: the context's library context (which outlives it) and property query, or the
    // default.
    let prov = unsafe { EvpProvider::new(libctx, propq) };
    Cache::new(&prov)
        .table
        .into_iter()
        .filter(|l| l.hash != NID_md5_sha1)
        .filter(|l| x.is_some() || !matches!(l.sig, Sig::Other(_)))
        .collect()
}

/// The number of built-in signature algorithms (`OSSL_NELEM(sigalg_lookup_tbl)`).
fn builtin_count(table: &[SigAlg]) -> usize {
    table
        .iter()
        .filter(|l| !matches!(l.sig, Sig::Other(_)))
        .count()
}

/// `get_sigorhash`: a signature type or a hash by name.
fn sig_or_hash(sig: &mut c_int, hash: &mut c_int, name: &[u8]) {
    let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
    if is("RSA") {
        *sig = NID_rsaEncryption;
    } else if is("RSA-PSS") || is("PSS") {
        *sig = NID_rsassaPss;
    } else if is("DSA") {
        *sig = NID_dsa;
    } else if is("ECDSA") {
        *sig = NID_X9_62_id_ecPublicKey;
    } else {
        let Ok(c) = CString::new(name) else {
            *hash = NID_undef;
            return;
        };
        // SAFETY: a C string.
        *hash = unsafe { OBJ_sn2nid(c.as_ptr()) };
        if *hash == NID_undef {
            // SAFETY: as above.
            *hash = unsafe { OBJ_ln2nid(c.as_ptr()) };
        }
    }
}

/// `tls1_set_sigalgs_list`'s parse: the code points of `s` (`name`, `sig+hash`, `?` to
/// ignore an unknown one), from the context's table (skipping unavailable ones) or, with
/// `checked` false, the built-in table; `None` on failure (with OpenSSL's error, if any).
fn sigalgs_list(table: &[SigAlg], with_ctx: bool, s: &[u8]) -> Option<Vec<u16>> {
    let max = builtin_count(table).saturating_mul(2);
    let mut out: Vec<u16> = Vec::new();
    let mut cb = |item: Option<&[u8]>| -> c_int {
        let Some(mut e) = item else { return 0 };
        let mut ignore_unknown = false;
        if let Some((b'?', rest)) = e.split_first() {
            ignore_unknown = true;
            e = rest;
        }
        if out.len() == max || e.len() > MAX_SIGSTRING {
            return 0;
        }
        let found = if let Some(plus) = e.iter().position(|&c| c == b'+') {
            let (a, b) = e.split_at(plus);
            let b = b.get(1..).unwrap_or_default();
            if b.is_empty() {
                return 0;
            }
            let (mut sig, mut hash) = (NID_undef, NID_undef);
            sig_or_hash(&mut sig, &mut hash, a);
            sig_or_hash(&mut sig, &mut hash, b);
            if sig == NID_undef || hash == NID_undef {
                None
            } else {
                table.iter().find(|l| l.hash == hash && sig_type(l) == sig)
            }
        } else {
            table.iter().find(|l| {
                l.name12
                    .is_some_and(|a| a.as_bytes().eq_ignore_ascii_case(e))
                    || l.name.as_bytes().eq_ignore_ascii_case(e)
            })
        };
        let Some(lu) = found else {
            return c_int::from(ignore_unknown);
        };
        if with_ctx && !lu.available {
            return 1;
        }
        if !out.contains(&lu.sigalg) {
            out.push(lu.sigalg);
        }
        1
    };
    if parse_list(s, b':', true, &mut cb) == 0 {
        return None;
    }
    if out.is_empty() {
        let text = format!(
            "No valid signature algorithms in '{}'",
            String::from_utf8_lossy(s)
        );
        err::raise_with_text(
            ERR_LIB_SSL,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "tls1_set_sigalgs_list",
            &text,
        );
        return None;
    }
    Some(out)
}

/// `tls1_set_sigalgs`: the code points of (hash NID, signature type) pairs from the built-in
/// table, or `None` (an odd count, or a pair it lacks).
fn sigalgs_from_nids(nids: &[c_int]) -> Option<Vec<u16>> {
    if nids.is_empty() || !nids.len().is_multiple_of(2) {
        return None;
    }
    let table = sigalg_table(None);
    nids.as_chunks::<2>()
        .0
        .iter()
        .map(|&[md, sig]| {
            table
                .iter()
                .find(|l| l.hash == md && sig_type(l) == sig)
                .map(|l| l.sigalg)
        })
        .collect()
}

/// The list string of a `*_LIST` command, or `None` with `CONF_parse_list`'s error.
///
/// # Safety
/// `parg` is NULL or a C string.
unsafe fn list_arg<'a>(parg: *mut c_void) -> Option<&'a [u8]> {
    if parg.is_null() {
        err::raise(ERR_LIB_CONF, CONF_R_LIST_CANNOT_BE_NULL, "CONF_parse_list");
        return None;
    }
    // SAFETY: the caller's string.
    Some(unsafe { CStr::from_ptr(parg.cast::<c_char>()) }.to_bytes())
}

/// The `int` array of a `SET_GROUPS`/`SET_SIGALGS` command.
///
/// # Safety
/// `parg` points to `larg` `int`s.
unsafe fn int_array<'a>(parg: *mut c_void, larg: c_long) -> Option<&'a [c_int]> {
    let n = usize::try_from(larg).ok()?;
    if n == 0 {
        return Some(&[]);
    }
    if parg.is_null() {
        return None;
    }
    // SAFETY: the caller's array of `n` ints.
    Some(unsafe { core::slice::from_raw_parts(parg.cast::<c_int>(), n) })
}

/// Sets the signature algorithms of a certificate configuration (`tls1_set_raw_sigalgs`).
fn set_sigalgs(cert: &mut Cert, list: Vec<u16>, client: bool) {
    if client {
        cert.client_sigalgs = Some(list);
    } else {
        cert.conf_sigalgs = Some(list);
    }
}

/// The list commands of `SSL_CTX_ctrl` (`ssl3_ctx_ctrl`), with the syntax checks it makes
/// before looking at the context; `None` for another command.
///
/// # Safety
/// `c` is NULL or a live context; `parg` is what `cmd` documents.
pub(crate) unsafe fn ctx_ctrl(
    c: *mut SSL_CTX,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    // SAFETY: the caller's guarantee.
    let x = unsafe { ctx(c) };
    if cmd == SSL_CTRL_SET_GROUPS_LIST && larg == 1 {
        let Some(x) = x else {
            err::raise(
                ERR_LIB_SSL,
                ERR_R_PASSED_NULL_PARAMETER,
                "tls1_set_groups_list",
            );
            return Some(0);
        };
        // SAFETY: the caller's string.
        let Some(s) = (unsafe { list_arg(parg) }) else {
            return Some(0);
        };
        return Some(c_long::from(groups_list(&implemented(x), s).is_some()));
    }
    let Some(x) = x else {
        if matches!(
            cmd,
            SSL_CTRL_SET_SIGALGS_LIST | SSL_CTRL_SET_CLIENT_SIGALGS_LIST
        ) {
            // SAFETY: the caller's string.
            let Some(s) = (unsafe { list_arg(parg) }) else {
                return Some(0);
            };
            return Some(c_long::from(
                sigalgs_list(&sigalg_table(None), false, s).is_some(),
            ));
        }
        return None;
    };
    let r = match cmd {
        SSL_CTRL_SET_TMP_ECDH => {
            if parg.is_null() {
                err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "ssl3_ctx_ctrl");
                return Some(0);
            }
            // SAFETY: the caller's EC_KEY.
            let Some(g) = (unsafe { groups_from_ec_key(parg.cast()) }) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_SET_GROUPS => {
            // SAFETY: the caller's array.
            let Some(g) = (unsafe { int_array(parg, larg) }).and_then(groups_from_nids) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_SET_GROUPS_LIST => {
            // SAFETY: the caller's string.
            let Some(s) = (unsafe { list_arg(parg) }) else {
                return Some(0);
            };
            let Some(g) = groups_list(&implemented(x), s) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_GET0_IMPLEMENTED_GROUPS => {
            let (min, max) = {
                let st = x.state();
                (st.min_proto_version, st.max_proto_version)
            };
            // SAFETY: the caller's stack, or NULL.
            c_long::from(unsafe {
                implemented_groups(&implemented(x), min, max, larg != 0, parg.cast())
            })
        }
        SSL_CTRL_SET_SIGALGS | SSL_CTRL_SET_CLIENT_SIGALGS => {
            // SAFETY: the caller's array.
            let Some(l) = (unsafe { int_array(parg, larg) }).and_then(sigalgs_from_nids) else {
                return Some(0);
            };
            set_sigalgs(&mut x.state().cert, l, cmd == SSL_CTRL_SET_CLIENT_SIGALGS);
            1
        }
        SSL_CTRL_SET_SIGALGS_LIST | SSL_CTRL_SET_CLIENT_SIGALGS_LIST => {
            // SAFETY: the caller's string.
            let Some(s) = (unsafe { list_arg(parg) }) else {
                return Some(0);
            };
            let Some(l) = sigalgs_list(&sigalg_table(Some(x)), true, s) else {
                return Some(0);
            };
            set_sigalgs(
                &mut x.state().cert,
                l,
                cmd == SSL_CTRL_SET_CLIENT_SIGALGS_LIST,
            );
            1
        }
        _ => return None,
    };
    Some(r)
}

/// `tls1_get0_implemented_groups`: pushes the names of the groups usable with versions
/// `min..=max` onto `out`, by code point (each once, unless `all`): 1, or 0.
///
/// # Safety
/// `out` is NULL or a live `STACK_OF(OPENSSL_CSTRING)`.
unsafe fn implemented_groups(
    table: &[GroupEntry],
    min: c_int,
    max: c_int,
    all: bool,
    out: *mut OPENSSL_STACK,
) -> c_int {
    if table.is_empty() || out.is_null() {
        return 0;
    }
    let mut picked: Vec<(u16, usize, &GroupEntry)> = table
        .iter()
        .enumerate()
        .filter(|(_, g)| !(g.mintls > 0 && max > 0 && g.mintls > max))
        .filter(|(_, g)| !(g.maxtls > 0 && min > 0 && g.maxtls < min))
        .map(|(i, g)| (g.id, i, g))
        .collect();
    picked.sort_by_key(|&(id, i, _)| (id, i));
    let mut last = 0u16;
    for (id, _, g) in picked {
        if !all && id == last {
            continue;
        }
        last = id;
        // SAFETY: the caller's stack; the name lives as long as the context.
        if unsafe { OPENSSL_sk_push(out, g.tlsname.as_ptr().cast()) } <= 0 {
            return 0;
        }
    }
    1
}

/// The connection's context (`s->ctx`).
fn ctx_of_ssl<'a>(x: &Ssl) -> Option<&'a Ctx> {
    let st = x.state();
    // SAFETY: the connection holds a reference to its context.
    unsafe { ctx_of(&st) }
}

/// Runs `f` on the connection's core connection with no lock held (it may call the
/// application's security callback), putting it back after; `None` before a handshake.
fn with_core<R>(x: &Ssl, f: impl FnOnce(&mut Connection) -> R) -> Option<R> {
    let mut c = x.state().drv.tls.take()?;
    let r = f(&mut c);
    let mut st = x.state();
    if st.drv.tls.is_none() {
        st.drv.tls = Some(c);
    }
    Some(r)
}

/// The list commands of `SSL_ctrl` (`ssl3_ctrl`), and the shared groups; `None` for another
/// command.
///
/// # Safety
/// `x` is the live connection; `parg` is what `cmd` documents.
pub(crate) unsafe fn ssl_ctrl(
    x: &Ssl,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    let r = match cmd {
        SSL_CTRL_SET_TMP_ECDH => {
            if parg.is_null() {
                err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "ssl3_ctrl");
                return Some(0);
            }
            // SAFETY: the caller's EC_KEY.
            let Some(g) = (unsafe { groups_from_ec_key(parg.cast()) }) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_SET_GROUPS => {
            // SAFETY: the caller's array.
            let Some(g) = (unsafe { int_array(parg, larg) }).and_then(groups_from_nids) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_SET_GROUPS_LIST => {
            // SAFETY: the caller's string.
            let Some(s) = (unsafe { list_arg(parg) }) else {
                return Some(0);
            };
            let Some(c) = ctx_of_ssl(x) else {
                return Some(0);
            };
            let Some(g) = groups_list(&implemented(c), s) else {
                return Some(0);
            };
            x.state().lists.groups = Some(g);
            1
        }
        SSL_CTRL_SET_SIGALGS | SSL_CTRL_SET_CLIENT_SIGALGS => {
            // SAFETY: the caller's array.
            let Some(l) = (unsafe { int_array(parg, larg) }).and_then(sigalgs_from_nids) else {
                return Some(0);
            };
            set_sigalgs(&mut x.state().cert, l, cmd == SSL_CTRL_SET_CLIENT_SIGALGS);
            1
        }
        SSL_CTRL_SET_SIGALGS_LIST | SSL_CTRL_SET_CLIENT_SIGALGS_LIST => {
            // SAFETY: the caller's string.
            let Some(s) = (unsafe { list_arg(parg) }) else {
                return Some(0);
            };
            let c = ctx_of_ssl(x);
            let Some(l) = sigalgs_list(&sigalg_table(c), c.is_some(), s) else {
                return Some(0);
            };
            set_sigalgs(
                &mut x.state().cert,
                l,
                cmd == SSL_CTRL_SET_CLIENT_SIGALGS_LIST,
            );
            1
        }
        SSL_CTRL_GET_GROUPS => {
            let st = x.state();
            let Some(tls) = st.drv.tls.as_ref() else {
                return Some(0);
            };
            let peer = &tls.negotiated().peer_groups;
            if !parg.is_null() {
                // SAFETY: the caller's array, sized by a first call with NULL.
                let out =
                    unsafe { core::slice::from_raw_parts_mut(parg.cast::<c_int>(), peer.len()) };
                for (o, &id) in out.iter_mut().zip(peer) {
                    *o = group_to_nid(id, true);
                }
            }
            c_long::try_from(peer.len()).unwrap_or(0)
        }
        SSL_CTRL_GET_SHARED_GROUP => {
            let n = i32::try_from(larg).unwrap_or(i32::MAX);
            let id = with_core(x, |c| {
                rustyssl_tls::conn::common::groups::shared_group(c, n)
            })
            .unwrap_or(0);
            if larg == -1 {
                c_long::from(id)
            } else {
                c_long::from(group_to_nid(id, true))
            }
        }
        _ => return None,
    };
    Some(r)
}

/// `validate_cert_type`: each of `val` is X.509 or a raw public key, once.
fn valid_cert_types(val: &[u8]) -> bool {
    let (mut rpk, mut x509) = (false, false);
    for &t in val {
        let seen = match c_int::from(t) {
            t if t == TLSEXT_cert_type_rpk => &mut rpk,
            t if t == TLSEXT_cert_type_x509 => &mut x509,
            _ => return false,
        };
        if *seen {
            return false;
        }
        *seen = true;
    }
    true
}

/// `set_cert_type`: the list (`val`, `len`): NULL and 0 clear it.
///
/// # Safety
/// `val` is NULL or points to `len` octets.
unsafe fn cert_types(val: *const u8, len: usize) -> Option<Option<Box<[u8]>>> {
    if val.is_null() && len == 0 {
        return Some(None);
    }
    if val.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller's octets.
    let v = unsafe { core::slice::from_raw_parts(val, len) };
    valid_cert_types(v).then(|| Some(v.into()))
}

/// Writes a `get0` result: the list's address (NULL for none) and length.
///
/// # Safety
/// `t` and `len` are writable.
unsafe fn put_cert_types(v: Option<&[u8]>, t: *mut *mut u8, len: *mut usize) {
    let (p, n) = v.map_or((ptr::null_mut(), 0), |v| (v.as_ptr().cast_mut(), v.len()));
    // SAFETY: the caller's slots.
    unsafe { t.write(p) };
    // SAFETY: as above.
    unsafe { len.write(n) };
}

/// Which certificate type list.
#[derive(Clone, Copy)]
enum Which {
    Client,
    Server,
}

impl Which {
    fn of(self, l: &mut Lists) -> &mut Option<Box<[u8]>> {
        match self {
            Self::Client => &mut l.client_cert_type,
            Self::Server => &mut l.server_cert_type,
        }
    }
}

/// `SSL_CTX_set1_*_cert_type`.
///
/// # Safety
/// `c` is NULL or a live context; `val` NULL or `len` octets.
unsafe fn ctx_set_cert_type(c: *mut SSL_CTX, w: Which, val: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ctx(c) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(v) = (unsafe { cert_types(val, len) }) else {
        return 0;
    };
    *w.of(&mut x.state().lists) = v;
    1
}

/// `SSL_set1_*_cert_type`.
///
/// # Safety
/// `s` is NULL or a live connection; `val` NULL or `len` octets.
unsafe fn ssl_set_cert_type(s: *mut SSL, w: Which, val: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(v) = (unsafe { cert_types(val, len) }) else {
        return 0;
    };
    *w.of(&mut x.state().lists) = v;
    1
}

/// `SSL_CTX_get0_*_cert_type`.
///
/// # Safety
/// `c` is a live context; `t` and `len` NULL or writable.
unsafe fn ctx_get0_cert_type(
    c: *const SSL_CTX,
    w: Which,
    t: *mut *mut u8,
    len: *mut usize,
) -> c_int {
    if t.is_null() || len.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ctx(c) }) else {
        return 0;
    };
    let mut st = x.state();
    // SAFETY: the caller's slots; the list stays at its address until replaced.
    unsafe { put_cert_types(w.of(&mut st.lists).as_deref(), t, len) };
    1
}

/// `SSL_get0_*_cert_type`.
///
/// # Safety
/// `s` is NULL or a live connection; `t` and `len` NULL or writable.
unsafe fn ssl_get0_cert_type(s: *const SSL, w: Which, t: *mut *mut u8, len: *mut usize) -> c_int {
    if t.is_null() || len.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        return 0;
    };
    let mut st = x.state();
    // SAFETY: the caller's slots; the list stays at its address until replaced.
    unsafe { put_cert_types(w.of(&mut st.lists).as_deref(), t, len) };
    1
}

ffi_export! {
    /// Sets the certificate types the context accepts from clients (RFC 7250: X.509 and raw
    /// public keys, each at most once; NULL and 0 for X.509 only): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `val` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_client_cert_type(ctx: *mut SSL_CTX, val: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_set_cert_type(ctx, Which::Client, val, len) }
    }
}

ffi_export! {
    /// Sets the certificate types for the context's servers, as for the client's.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `val` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_server_cert_type(ctx: *mut SSL_CTX, val: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_set_cert_type(ctx, Which::Server, val, len) }
    }
}

ffi_export! {
    /// Sets the connection's client certificate types, as for the context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `val` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_client_cert_type(s: *mut SSL, val: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl_set_cert_type(s, Which::Client, val, len) }
    }
}

ffi_export! {
    /// Sets the connection's server certificate types, as for the context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `val` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_server_cert_type(s: *mut SSL, val: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl_set_cert_type(s, Which::Server, val, len) }
    }
}

ffi_export! {
    /// The context's client certificate types (NULL and 0 when unset), owned by the context:
    /// 1, or 0 for a NULL slot.
    ///
    /// # Safety
    /// `ctx` is a live context; `t` and `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_client_cert_type(ctx: *const SSL_CTX, t: *mut *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_get0_cert_type(ctx, Which::Client, t, len) }
    }
}

ffi_export! {
    /// The context's server certificate types, as for the client's.
    ///
    /// # Safety
    /// `ctx` is a live context; `t` and `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_server_cert_type(ctx: *const SSL_CTX, t: *mut *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_get0_cert_type(ctx, Which::Server, t, len) }
    }
}

ffi_export! {
    /// The connection's client certificate types, as for the context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `t` and `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_client_cert_type(s: *const SSL, t: *mut *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl_get0_cert_type(s, Which::Client, t, len) }
    }
}

ffi_export! {
    /// The connection's server certificate types, as for the context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `t` and `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_server_cert_type(s: *const SSL, t: *mut *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl_get0_cert_type(s, Which::Server, t, len) }
    }
}

ffi_export! {
    /// The TLS name of the group the connection negotiated (from its context's providers), or
    /// NULL (none yet, or a group they don't name).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_group_name(s: *mut SSL) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        let id = x.state().drv.tls.as_ref().and_then(|c| c.negotiated().group);
        let (Some(id), Some(c)) = (id, ctx_of_ssl(x)) else { return ptr::null() };
        // The context's table keeps its names for its lifetime.
        implemented(c).iter().find(|g| g.id == id).map_or(ptr::null(), |g| g.tlsname.as_ptr())
    }
}

ffi_export! {
    /// The built-in signature algorithms the library context's providers can do, by IANA
    /// name, colon-separated, which the caller frees; NULL on failure.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn rustyssl_private_SSL_get1_builtin_sigalgs(libctx: *mut OSSL_LIB_CTX) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let tmp = unsafe { EVP_PKEY_new() };
        let mut names: Vec<u8> = Vec::new();
        for lu in sigalg_table(None) {
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            // SAFETY: the caller's library context; the hash, its key type, and the key.
            let enabled = unsafe { builtin_enabled(libctx, tmp, &lu) };
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            if enabled {
                if !names.is_empty() {
                    names.push(b':');
                }
                names.extend_from_slice(lu.name.as_bytes());
            }
        }
        // SAFETY: the key made above (or NULL).
        unsafe { EVP_PKEY_free(tmp) };
        c_dup(&names)
    }
}

/// Whether the providers of `libctx` have a built-in algorithm's hash and signature type
/// (`SSL_get1_builtin_sigalgs`'s check).
///
/// # Safety
/// `libctx` is NULL or a live library context; `tmp` NULL or a key to retype.
unsafe fn builtin_enabled(
    libctx: *mut OSSL_LIB_CTX,
    tmp: *mut rustyssl_abi::EVP_PKEY,
    lu: &SigAlg,
) -> bool {
    if lu.hash != NID_undef {
        // SAFETY: a NID's name (static, or NULL).
        let name = unsafe { OBJ_nid2ln(lu.hash) };
        // SAFETY: the caller's library context and the name.
        let md = unsafe { EVP_MD_fetch(libctx, name, ptr::null()) };
        if md.is_null() {
            return false;
        }
        // SAFETY: fetched above.
        unsafe { EVP_MD_free(md) };
    }
    // SAFETY: the caller's key, or NULL (which fails).
    if unsafe { EVP_PKEY_set_type(tmp, sig_type(lu)) } == 0 {
        return false;
    }
    // SAFETY: the caller's library context and the key.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, tmp, ptr::null()) };
    let ok = !pctx.is_null();
    // SAFETY: made above, or NULL.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    ok
}

ffi_export! {
    /// The suites of the connection's cipher list it can use now (its version range, its
    /// signature algorithms, PSK and SRP, and the security level or callback), as a new stack
    /// the caller frees; NULL for none.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get1_supported_ciphers(s: *mut SSL) -> *mut stack_st_SSL_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        // SAFETY: the live connection.
        if unsafe { super::ciphers::ssl_ciphers(s) }.is_null() {
            return ptr::null_mut();
        }
        let Some(snap) = super::io::config::snapshot(x) else { return ptr::null_mut() };
        // SAFETY: the connection's context's snapshot.
        let prov = unsafe { super::io::provider(x, &snap) };
        // SAFETY: the live connection and its context's snapshot.
        let mut cfg = unsafe { super::io::config::build(s, x, &snap, &prov) };
        // SAFETY: the live connection.
        let hook = unsafe { super::io::security_hook(s, x) };
        cfg.custom_security_callback = hook.is_some();
        let mut c = Connection::new(cfg);
        c.set_security_hook(hook);
        // No lock is held: the security callback may run.
        let Some(list) = rustyssl_tls::conn::common::ciphers::supported(&mut c, &*prov) else {
            return ptr::null_mut();
        };
        // QUIC leaves out the suites it can't use (`ssl_cipher_disabled`).
        // SAFETY: the caller's guarantee.
        let list: Vec<_> = if unsafe { super::quic::of(s) }.is_some() {
            list.into_iter().filter(|c| super::quic::quic_suite(c)).collect()
        } else {
            list
        };
        if list.is_empty() {
            return ptr::null_mut();
        }
        super::ciphers::CipherStack::of(&list).map_or(ptr::null_mut(), super::ciphers::CipherStack::into_raw)
    }
}
