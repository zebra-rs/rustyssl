//! Certificate policies in path validation (`pcy_cache.c`, `pcy_data.c`, `pcy_map.c`,
//! `pcy_node.c`, `pcy_tree.c`, `pcy_lib.c`, `X509_POLICY_NODE_print` of `v3_cpols.c`, and
//! `check_policy` of `x509_vfy.c`): RFC 5280's valid policy tree. Each certificate's
//! policies, mappings, and constraints are cached on it once; `X509_policy_check` grows the
//! tree a level per certificate below the trust anchor, prunes it, and takes the authority
//! and user policy sets from it, as OpenSSL does, with at most 1,000 nodes (OpenSSL's bound
//! since CVE-2023-0464, whose chains of mappings grow trees exponentially).
//!
//! The tree, its levels, and its nodes are opaque in the headers: here they're Rust objects
//! whose addresses the getters hand out, all freed with the tree. The policy sets are C stacks
//! of nodes, as the getters return them.

use core::cell::Cell;
use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OBJECT, BIO, ERR_LIB_X509, ERR_R_CRYPTO_LIB, ERR_R_INTERNAL_ERROR,
    ERR_R_X509_LIB, EXFLAG_INVALID_POLICY, EXFLAG_SI, NID_any_policy, NID_certificate_policies,
    NID_inhibit_any_policy, NID_policy_constraints, NID_policy_mappings, OPENSSL_STACK,
    POLICY_CONSTRAINTS, POLICY_MAPPING, POLICYINFO, V_ASN1_NEG_INTEGER, X509, X509_PCY_TREE_EMPTY,
    X509_PCY_TREE_EXPLICIT, X509_PCY_TREE_FAILURE, X509_PCY_TREE_INTERNAL, X509_PCY_TREE_INVALID,
    X509_PCY_TREE_VALID, X509_POLICY_LEVEL, X509_POLICY_NODE, X509_POLICY_TREE, X509_STORE_CTX,
    X509_V_ERR_INVALID_POLICY_EXTENSION, X509_V_ERR_NO_EXPLICIT_POLICY, X509_V_ERR_OUT_OF_MEM,
    X509_V_FLAG_EXPLICIT_POLICY, X509_V_FLAG_INHIBIT_ANY, X509_V_FLAG_INHIBIT_MAP,
    X509_V_FLAG_NOTIFY_POLICY, stack_st_ASN1_OBJECT, stack_st_POLICYQUALINFO, stack_st_X509,
    stack_st_X509_POLICY_NODE,
};

use super::cert::{X509_free, X509_up_ref, cert_of};
use super::ctx::{ctx_of, verify_cb_cert};
use super::purpose::{X509_check_purpose, X509_get_ext_d2i, X509_get_extension_flags, cache_view};
use super::vpm::Param;
use crate::asn1::integer::ASN1_INTEGER_get;
use crate::asn1::string::ASN1_INTEGER_free;
use crate::bio::BIO_puts;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::{
    ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_obj2nid, i2a_ASN1_OBJECT,
};
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value,
};
use crate::threads::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::x509v3::policy::{
    POLICY_CONSTRAINTS_free, POLICYQUALINFO_free, free_pmap, free_pol, print_qualifiers,
};

/// `OPENSSL_POLICY_TREE_NODES_MAX`: the most nodes a tree grows (CVE-2023-0464).
const NODES_MAX: usize = 1000;

// A policy's flags (`POLICY_DATA_FLAG_*`).
/// Mapped by the certificate's policy mappings.
const MAPPED: c_uint = 0x1;
/// Mapped, through `anyPolicy`.
const MAPPED_ANY: c_uint = 0x2;
/// Either.
const MAP_MASK: c_uint = 0x3;
/// The qualifiers are another policy's.
const SHARED_QUALIFIERS: c_uint = 0x4;
/// A user policy's node outside the tree.
const EXTRA_NODE: c_uint = 0x8;
/// The certificate policies extension is critical.
const CRITICAL: c_uint = 0x10;

/// The tree's flag (`POLICY_FLAG_ANY_POLICY`): the user policies include `anyPolicy`.
const ANY_POLICY: c_uint = 0x2;

/// A flag of `x509_vfy.h` (all positive) as a level's or the check's `unsigned int`.
fn vflag(v: c_int) -> c_uint {
    v.cast_unsigned()
}

/// An `EXFLAG_*` (all positive) as the cache's `u32`.
fn ex(v: c_int) -> u32 {
    v.cast_unsigned()
}

/// Whether the objects are equal (`OBJ_cmp`).
fn same(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> bool {
    // SAFETY: live objects, as every policy's and every caller's are.
    unsafe { OBJ_cmp(a, b) == 0 }
}

/// Whether the object is `anyPolicy`.
fn is_any(o: *const ASN1_OBJECT) -> bool {
    // SAFETY: as above.
    unsafe { OBJ_obj2nid(o) == NID_any_policy }
}

/// `X509_POLICY_DATA`: a policy, with its qualifiers and what it maps to.
pub(crate) struct Data {
    flags: c_uint,
    valid_policy: *mut ASN1_OBJECT,
    qualifier_set: *mut stack_st_POLICYQUALINFO,
    expected_policy_set: Vec<*mut ASN1_OBJECT>,
}

impl Drop for Data {
    fn drop(&mut self) {
        // SAFETY: its own object.
        unsafe { ASN1_OBJECT_free(self.valid_policy) };
        if self.flags & SHARED_QUALIFIERS == 0 {
            // SAFETY: its own qualifiers, or NULL.
            unsafe { OPENSSL_sk_pop_free(self.qualifier_set.cast(), Some(free_qual)) };
        }
        for o in self.expected_policy_set.drain(..) {
            // SAFETY: its own objects.
            unsafe { ASN1_OBJECT_free(o) };
        }
    }
}

/// `POLICYQUALINFO_free` as a stack's free function.
unsafe extern "C" fn free_qual(p: *mut c_void) {
    // SAFETY: a qualifier of the stack, which the stack owned.
    unsafe { POLICYQUALINFO_free(p.cast()) };
}

/// The policy behind a pointer.
///
/// # Safety
/// `p` is a live policy (a certificate's cache's or a tree's, which outlive their uses).
unsafe fn data<'a>(p: *const Data) -> &'a Data {
    // SAFETY: the caller's guarantee.
    unsafe { &*p }
}

/// `ossl_policy_data_new`: a policy taking `policy`'s identifier (or a copy of `cid`) and its
/// qualifiers, or `None`.
///
/// # Safety
/// `policy` is a live policy information; `cid` is NULL or a live object.
unsafe fn data_new(
    policy: Option<&mut POLICYINFO>,
    cid: *const ASN1_OBJECT,
    crit: bool,
) -> Option<Box<Data>> {
    if policy.is_none() && cid.is_null() {
        return None;
    }
    let valid_policy = if cid.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's object.
        let id = unsafe { OBJ_dup(cid) };
        if id.is_null() {
            return None;
        }
        id
    };
    let mut ret = Box::new(Data {
        flags: if crit { CRITICAL } else { 0 },
        valid_policy,
        qualifier_set: ptr::null_mut(),
        expected_policy_set: Vec::new(),
    });
    if let Some(policy) = policy {
        if cid.is_null() {
            ret.valid_policy = core::mem::replace(&mut policy.policyid, ptr::null_mut());
        }
        ret.qualifier_set = core::mem::replace(&mut policy.qualifiers, ptr::null_mut());
    }
    Some(ret)
}

/// `X509_POLICY_CACHE`: a certificate's policies, mappings, and constraints, made once.
pub(crate) struct PolicyCache {
    any_policy: *mut Data,
    /// The policies but `anyPolicy` (none, NULL, without the extension), sorted, then the
    /// policies `anyPolicy` was mapped to.
    data: Option<Vec<*mut Data>>,
    any_skip: c_long,
    explicit_skip: c_long,
    map_skip: c_long,
}

impl Drop for PolicyCache {
    fn drop(&mut self) {
        for p in self
            .data
            .take()
            .into_iter()
            .flatten()
            .chain([self.any_policy])
        {
            if !p.is_null() {
                // SAFETY: its own policies, made by `Box::into_raw`.
                drop(unsafe { Box::from_raw(p) });
            }
        }
    }
}

impl PolicyCache {
    /// `ossl_policy_cache_find_data`.
    fn find(&self, id: *const ASN1_OBJECT) -> Option<*mut Data> {
        self.data.as_ref()?.iter().copied().find(|&d| {
            // SAFETY: its own policies.
            same(unsafe { data(d) }.valid_policy, id)
        })
    }
}

/// Frees a certificate's policy cache (`ossl_policy_cache_free`; nothing for NULL).
///
/// # Safety
/// `cache` is NULL or a cache made here, not used after.
pub(crate) unsafe fn cache_free(cache: *mut PolicyCache) {
    if !cache.is_null() {
        // SAFETY: the caller's guarantee; made by `Box::into_raw`.
        drop(unsafe { Box::from_raw(cache) });
    }
}

/// `policy_cache_set_int`: a skip count from a constraint (none for NULL); false for a
/// negative one.
///
/// # Safety
/// `value` is NULL or a live integer.
unsafe fn set_int(out: &mut c_long, value: *const ASN1_INTEGER) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { value.as_ref() }) else {
        return true;
    };
    if v.type_ == V_ASN1_NEG_INTEGER {
        return false;
    }
    // SAFETY: as above.
    *out = unsafe { ASN1_INTEGER_get(value) };
    true
}

/// `policy_cache_create`: the cache's policies from the certificate policies (freed): 1, 0,
/// or -1 for duplicates (invalid).
///
/// # Safety
/// `policies` is a live list of policy information the function takes.
unsafe fn cache_create(cache: &mut PolicyCache, policies: *mut c_void, crit: bool) -> c_int {
    // SAFETY: the caller's list.
    let num = unsafe { OPENSSL_sk_num(policies.cast()) };
    let mut ret = 0;
    if num > 0 {
        let mut list: Vec<*mut Data> = Vec::new();
        ret = 1;
        for i in 0..num {
            // SAFETY: an index within the list.
            let policy = unsafe { OPENSSL_sk_value(policies.cast(), i) }.cast::<POLICYINFO>();
            // SAFETY: a live policy information, or NULL.
            let new = unsafe { policy.as_mut() }.and_then(|p| {
                // SAFETY: a live policy information.
                unsafe { data_new(Some(p), ptr::null(), crit) }
            });
            let Some(d) = new else {
                err::raise(
                    rustyssl_abi::ERR_LIB_X509V3,
                    ERR_R_X509_LIB,
                    "policy_cache_create",
                );
                ret = 0;
                break;
            };
            let id = d.valid_policy;
            if is_any(id) {
                if !cache.any_policy.is_null() {
                    ret = -1;
                    break;
                }
                cache.any_policy = Box::into_raw(d);
            } else if list.iter().any(|&e| {
                // SAFETY: the list's policies.
                same(unsafe { data(e) }.valid_policy, id)
            }) {
                ret = -1;
                break;
            } else {
                list.push(Box::into_raw(d));
            }
        }
        if ret == 1 {
            list.sort_by(|&a, &b| {
                // SAFETY: the list's policies.
                let a = unsafe { data(a) }.valid_policy;
                // SAFETY: as above.
                let b = unsafe { data(b) }.valid_policy;
                // SAFETY: their objects.
                unsafe { OBJ_cmp(a, b) }.cmp(&0)
            });
            cache.data = Some(list);
        } else {
            for p in list {
                // SAFETY: made above by `Box::into_raw`.
                drop(unsafe { Box::from_raw(p) });
            }
        }
    }
    // SAFETY: the caller's list, which the function took.
    unsafe { OPENSSL_sk_pop_free(policies.cast(), Some(free_pol)) };
    ret
}

/// `ossl_policy_cache_set_mapping`: maps the cache's policies (and `anyPolicy`'s) with the
/// policy mappings (freed): 1, 0, or -1 for none or a mapping of `anyPolicy` (invalid).
///
/// # Safety
/// `maps` is a live list of mappings the function takes.
unsafe fn set_mapping(cache: &mut PolicyCache, maps: *mut c_void) -> c_int {
    let ret = 'mapping: {
        // SAFETY: the caller's list.
        let n = unsafe { OPENSSL_sk_num(maps.cast()) };
        if n == 0 {
            break 'mapping -1;
        }
        for i in 0..n {
            // SAFETY: an index within the list.
            let map = unsafe { OPENSSL_sk_value(maps.cast(), i) }.cast::<POLICY_MAPPING>();
            // SAFETY: a live mapping.
            let Some(map) = (unsafe { map.as_mut() }) else {
                break 'mapping 0;
            };
            if is_any(map.subjectDomainPolicy) || is_any(map.issuerDomainPolicy) {
                break 'mapping -1;
            }
            let d = if let Some(d) = cache.find(map.issuerDomainPolicy) {
                // SAFETY: the cache's policy, which nothing else holds now.
                unsafe { (*d).flags |= MAPPED };
                d
            } else {
                // SAFETY: the cache's `anyPolicy`, or NULL.
                let Some(any) = (unsafe { cache.any_policy.as_ref() }) else {
                    continue;
                };
                let (crit, quals) = (any.flags & CRITICAL != 0, any.qualifier_set);
                // SAFETY: the mapping's object.
                let Some(mut d) = (unsafe { data_new(None, map.issuerDomainPolicy, crit) }) else {
                    break 'mapping 0;
                };
                d.qualifier_set = quals;
                d.flags |= MAPPED_ANY | SHARED_QUALIFIERS;
                let d = Box::into_raw(d);
                cache.data.get_or_insert_with(Vec::new).push(d);
                d
            };
            let subject = core::mem::replace(&mut map.subjectDomainPolicy, ptr::null_mut());
            // SAFETY: as above.
            unsafe { (*d).expected_policy_set.push(subject) };
        }
        1
    };
    // SAFETY: the caller's list, which the function took.
    unsafe { OPENSSL_sk_pop_free(maps.cast(), Some(free_pmap)) };
    ret
}

/// `policy_cache_new`: the certificate's cache, and whether its policy extensions are
/// invalid.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn cache_new(x: *const X509) -> (Box<PolicyCache>, bool) {
    let mut cache = Box::new(PolicyCache {
        any_policy: ptr::null_mut(),
        data: None,
        any_skip: -1,
        explicit_skip: -1,
        map_skip: -1,
    });
    let d2i = |nid, i: &mut c_int| {
        // SAFETY: the caller's certificate.
        unsafe { X509_get_ext_d2i(x, nid, i, ptr::null_mut()) }
    };
    let mut i = 0;
    let pcons = d2i(NID_policy_constraints, &mut i).cast::<POLICY_CONSTRAINTS>();
    let mut ext_any: *mut ASN1_INTEGER = ptr::null_mut();
    let bad = 'bad: {
        // SAFETY: the decoded constraints, or NULL.
        if let Some(pc) = unsafe { pcons.as_ref() } {
            if pc.requireExplicitPolicy.is_null() && pc.inhibitPolicyMapping.is_null() {
                break 'bad true;
            }
            // SAFETY: their integers, or NULL.
            if !unsafe { set_int(&mut cache.explicit_skip, pc.requireExplicitPolicy) }
                // SAFETY: as above.
                || !unsafe { set_int(&mut cache.map_skip, pc.inhibitPolicyMapping) }
            {
                break 'bad true;
            }
        } else if i != -1 {
            break 'bad true;
        }
        let cpols = d2i(NID_certificate_policies, &mut i);
        if cpols.is_null() {
            if i != -1 {
                break 'bad true;
            }
            break 'bad false;
        }
        // SAFETY: the decoded policies, which it takes.
        let r = unsafe { cache_create(&mut cache, cpols, i != 0) };
        if r <= 0 {
            // Duplicates have made it invalid.
            break 'bad r < 0;
        }
        let pmaps = d2i(NID_policy_mappings, &mut i);
        if pmaps.is_null() {
            if i != -1 {
                break 'bad true;
            }
        // SAFETY: the decoded mappings, which it takes.
        } else if unsafe { set_mapping(&mut cache, pmaps) } <= 0 {
            break 'bad true;
        }
        ext_any = d2i(NID_inhibit_any_policy, &mut i).cast();
        if ext_any.is_null() {
            if i != -1 {
                break 'bad true;
            }
        // SAFETY: the decoded integer.
        } else if !unsafe { set_int(&mut cache.any_skip, ext_any) } {
            break 'bad true;
        }
        false
    };
    // SAFETY: decoded above, or NULL.
    unsafe { POLICY_CONSTRAINTS_free(pcons) };
    // SAFETY: as above.
    unsafe { ASN1_INTEGER_free(ext_any) };
    (cache, bad)
}

/// `ossl_policy_cache_set`: the certificate's cache, made on first use (under its lock,
/// marking it `EXFLAG_INVALID_POLICY` if its extensions are invalid), or NULL.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn cache_set(x: *const X509) -> *const PolicyCache {
    // SAFETY: the caller's guarantee.
    let Some(lock) = (unsafe { cert_of(x) }).map(|c| c.lock) else {
        return ptr::null();
    };
    // SAFETY: its lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return ptr::null();
    }
    // SAFETY: as above, under its lock.
    let missing = unsafe { cert_of(x) }.is_some_and(|c| c.cache.policy_cache.is_null());
    if missing {
        // SAFETY: as above.
        let (cache, bad) = unsafe { cache_new(x) };
        // SAFETY: as above.
        if let Some(c) = unsafe { cert_of(x) } {
            c.cache.policy_cache = Box::into_raw(cache);
            if bad {
                c.cache.flags |= ex(EXFLAG_INVALID_POLICY);
            }
        }
    }
    // SAFETY: as above.
    let cache = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cache.policy_cache);
    // SAFETY: locked above.
    unsafe { CRYPTO_THREAD_unlock(lock) };
    cache
}

/// `X509_POLICY_NODE`: a node of the tree.
pub(crate) struct Node {
    data: *const Data,
    parent: *const Node,
    nchild: Cell<c_int>,
}

/// The node behind a pointer.
///
/// # Safety
/// `p` is a live node (its tree's, which outlives its uses).
unsafe fn node<'a>(p: *const Node) -> &'a Node {
    // SAFETY: the caller's guarantee.
    unsafe { &*p }
}

/// Counts a child more or less for the node's parent, if any.
fn adopt(parent: *const Node, delta: c_int) {
    // SAFETY: a node's parent is NULL or a node of its tree.
    if let Some(p) = unsafe { parent.as_ref() } {
        p.nchild.set(p.nchild.get().wrapping_add(delta));
    }
}

/// The node's policy.
fn node_data<'a>(p: *const Node) -> &'a Data {
    // SAFETY: a tree's node, with its policy.
    let d = unsafe { node(p) }.data;
    // SAFETY: as above.
    unsafe { data(d) }
}

/// `X509_POLICY_LEVEL`: the nodes for one certificate.
pub(crate) struct Level {
    cert: *mut X509,
    nodes: Vec<*mut Node>,
    any_policy: *mut Node,
    flags: c_uint,
}

/// `X509_POLICY_TREE`.
pub(crate) struct Tree {
    node_count: usize,
    node_maximum: usize,
    levels: Box<[Level]>,
    /// Every node made, freed with the tree.
    all_nodes: Vec<*mut Node>,
    /// The policies made for the tree, freed with it.
    extra_data: Vec<*mut Data>,
    auth_policies: *mut OPENSSL_STACK,
    user_policies: *mut OPENSSL_STACK,
    flags: c_uint,
}

impl Drop for Tree {
    fn drop(&mut self) {
        // SAFETY: its own lists (the nodes are its own, freed below).
        unsafe { OPENSSL_sk_free(self.auth_policies) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(self.user_policies) };
        for l in &*self.levels {
            // SAFETY: its own reference, or NULL.
            unsafe { X509_free(l.cert) };
        }
        for n in self.all_nodes.drain(..) {
            // SAFETY: made by `Box::into_raw`.
            drop(unsafe { Box::from_raw(n) });
        }
        for d in self.extra_data.drain(..) {
            // SAFETY: as above.
            drop(unsafe { Box::from_raw(d) });
        }
    }
}

impl Tree {
    fn level(&self, i: usize) -> Option<&Level> {
        self.levels.get(i)
    }

    fn level_mut(&mut self, i: usize) -> Option<&mut Level> {
        self.levels.get_mut(i)
    }

    /// `ossl_policy_level_add_node`: a node for `data` under `parent`, on level `level` (or
    /// none, for a user policy), the tree taking `data` if `extra`; NULL once the tree is at
    /// its maximum, or for a second `anyPolicy` on a level.
    fn add_node(
        &mut self,
        level: Option<usize>,
        data: *mut Data,
        parent: *const Node,
        extra: bool,
    ) -> *mut Node {
        if self.node_maximum > 0 && self.node_count >= self.node_maximum || data.is_null() {
            return ptr::null_mut();
        }
        let n = Box::into_raw(Box::new(Node {
            data,
            parent,
            nchild: Cell::new(0),
        }));
        if let Some(l) = level.and_then(|i| self.level_mut(i)) {
            // SAFETY: a live policy, its cache's or the tree's.
            if is_any(unsafe { (*data).valid_policy }) {
                if !l.any_policy.is_null() {
                    // SAFETY: made above.
                    drop(unsafe { Box::from_raw(n) });
                    return ptr::null_mut();
                }
                l.any_policy = n;
            } else {
                l.nodes.push(n);
            }
        }
        if extra {
            self.extra_data.push(data);
        }
        self.all_nodes.push(n);
        self.node_count += 1;
        adopt(parent, 1);
        n
    }
}

/// `ossl_policy_node_match`: whether the node (on `lvl`) matches `oid`: its policy, or with
/// mapping its expected ones.
fn node_match(lvl: &Level, n: *const Node, oid: *const ASN1_OBJECT) -> bool {
    let x = node_data(n);
    if lvl.flags & vflag(X509_V_FLAG_INHIBIT_MAP) != 0 || x.flags & MAP_MASK == 0 {
        return same(x.valid_policy, oid);
    }
    x.expected_policy_set.iter().any(|&p| same(p, oid))
}

/// `ossl_policy_level_find_node`: the level's node for `id` under `parent`.
fn level_find_node(lvl: &Level, parent: *const Node, id: *const ASN1_OBJECT) -> bool {
    lvl.nodes.iter().any(|&n| {
        // SAFETY: the level's node.
        let nd = unsafe { node(n) };
        ptr::eq(nd.parent, parent) && same(node_data(n).valid_policy, id)
    })
}

/// The certificate's cache, made already.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn cache_of<'a>(x: *const X509) -> Option<&'a PolicyCache> {
    // SAFETY: the caller's guarantee; a cache lives as long as its certificate, and doesn't
    // change once made.
    let p = unsafe { cache_set(x) };
    // SAFETY: as above.
    unsafe { p.as_ref() }
}

/// `tree_init`: the tree's levels from the chain (the trust anchor last, not counted), with
/// what the constraints and flags inhibit: the tree (unless invalid, empty, or failing) and
/// `X509_PCY_TREE_*` flags.
///
/// # Safety
/// `certs` is NULL or a live list of live certificates.
unsafe fn tree_init(certs: *mut stack_st_X509, flags: c_uint) -> (c_int, Option<Box<Tree>>) {
    // SAFETY: the caller's list.
    let n = unsafe { OPENSSL_sk_num(certs.cast()) } - 1;
    let cert = |i| {
        // SAFETY: an index within the list.
        unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>()
    };
    let start = |flag| if flags & vflag(flag) != 0 { 0 } else { n + 1 };
    let mut explicit_policy = start(X509_V_FLAG_EXPLICIT_POLICY);
    let mut any_skip = start(X509_V_FLAG_INHIBIT_ANY);
    let mut map_skip = start(X509_V_FLAG_INHIBIT_MAP);
    if n < 0 {
        return (X509_PCY_TREE_INTERNAL, None);
    }
    if n == 0 {
        return (X509_PCY_TREE_EMPTY, None);
    }
    // Every certificate's extensions and policies cached first.
    for i in (0..n).rev() {
        // SAFETY: a certificate of the list, or NULL.
        unsafe { X509_check_purpose(cert(i), -1, 0) };
        // SAFETY: as above.
        if unsafe { cache_set(cert(i)) }.is_null() {
            return (X509_PCY_TREE_INTERNAL, None);
        }
    }
    let mut ret = X509_PCY_TREE_VALID;
    let mut i = n - 1;
    while i >= 0 && (explicit_policy > 0 || ret & X509_PCY_TREE_EMPTY == 0) {
        let x = cert(i);
        // SAFETY: as above.
        let ex_flags = unsafe { X509_get_extension_flags(x) };
        if ex_flags & ex(EXFLAG_INVALID_POLICY) != 0 {
            return (X509_PCY_TREE_INVALID, None);
        }
        // SAFETY: as above.
        let Some(cache) = (unsafe { cache_of(x) }) else {
            return (X509_PCY_TREE_INTERNAL, None);
        };
        if ret & X509_PCY_TREE_VALID != 0 && cache.data.is_none() {
            ret = X509_PCY_TREE_EMPTY;
        }
        if explicit_policy > 0 {
            if ex_flags & ex(EXFLAG_SI) == 0 {
                explicit_policy -= 1;
            }
            if cache.explicit_skip >= 0 && cache.explicit_skip < c_long::from(explicit_policy) {
                explicit_policy = c_int::try_from(cache.explicit_skip).unwrap_or(explicit_policy);
            }
        }
        i -= 1;
    }
    if explicit_policy == 0 {
        ret |= X509_PCY_TREE_EXPLICIT;
    }
    if ret & X509_PCY_TREE_VALID == 0 {
        return (ret, None);
    }
    let Ok(nlevels) = usize::try_from(n + 1) else {
        return (X509_PCY_TREE_INTERNAL, None);
    };
    let mut tree = Box::new(Tree {
        node_count: 0,
        node_maximum: NODES_MAX,
        levels: (0..nlevels)
            .map(|_| Level {
                cert: ptr::null_mut(),
                nodes: Vec::new(),
                any_policy: ptr::null_mut(),
                flags: 0,
            })
            .collect(),
        all_nodes: Vec::new(),
        extra_data: Vec::new(),
        auth_policies: ptr::null_mut(),
        user_policies: ptr::null_mut(),
        flags: 0,
    });
    // The trust anchor's level: `anyPolicy`.
    // SAFETY: a NID.
    let any = unsafe { OBJ_nid2obj(NID_any_policy) };
    // SAFETY: the static object.
    let Some(d) = (unsafe { data_new(None, any, false) }) else {
        return (X509_PCY_TREE_INTERNAL, None);
    };
    let d = Box::into_raw(d);
    if tree.add_node(Some(0), d, ptr::null(), true).is_null() {
        // SAFETY: made above, not taken.
        drop(unsafe { Box::from_raw(d) });
        return (X509_PCY_TREE_INTERNAL, None);
    }
    let mut level = 0;
    for i in (0..n).rev() {
        let x = cert(i);
        // SAFETY: as above.
        let ex_flags = unsafe { X509_get_extension_flags(x) };
        // SAFETY: as above.
        let Some(cache) = (unsafe { cache_of(x) }) else {
            return (X509_PCY_TREE_INTERNAL, None);
        };
        // SAFETY: as above.
        if unsafe { X509_up_ref(x) } == 0 {
            return (X509_PCY_TREE_INTERNAL, None);
        }
        level += 1;
        let Some(l) = tree.level_mut(level) else {
            // SAFETY: the reference just taken.
            unsafe { X509_free(x) };
            return (X509_PCY_TREE_INTERNAL, None);
        };
        l.cert = x;
        if cache.any_policy.is_null() {
            l.flags |= vflag(X509_V_FLAG_INHIBIT_ANY);
        }
        let si = ex_flags & ex(EXFLAG_SI) != 0;
        if any_skip == 0 {
            if !si || i == 0 {
                l.flags |= vflag(X509_V_FLAG_INHIBIT_ANY);
            }
        } else {
            if !si {
                any_skip -= 1;
            }
            if cache.any_skip >= 0 && cache.any_skip < c_long::from(any_skip) {
                any_skip = c_int::try_from(cache.any_skip).unwrap_or(any_skip);
            }
        }
        if map_skip == 0 {
            l.flags |= vflag(X509_V_FLAG_INHIBIT_MAP);
        } else {
            if !si {
                map_skip -= 1;
            }
            if cache.map_skip >= 0 && cache.map_skip < c_long::from(map_skip) {
                map_skip = c_int::try_from(cache.map_skip).unwrap_or(map_skip);
            }
        }
    }
    (ret, Some(tree))
}

/// `tree_link_matching_nodes`: a node for `data` under each node of the level above that it
/// matches, or under that level's `anyPolicy`.
fn link_matching_nodes(tree: &mut Tree, curr: usize, data: *mut Data) -> bool {
    let Some(last) = curr.checked_sub(1) else {
        return false;
    };
    // SAFETY: a cache's policy.
    let id = unsafe { (*data).valid_policy };
    let (nodes, any) = match tree.level(last) {
        Some(l) => (
            l.nodes
                .iter()
                .copied()
                .filter(|&n| node_match(l, n, id))
                .collect::<Vec<_>>(),
            l.any_policy,
        ),
        None => return false,
    };
    for &n in &nodes {
        if tree.add_node(Some(curr), data, n, false).is_null() {
            return false;
        }
    }
    if nodes.is_empty() && !any.is_null() && tree.add_node(Some(curr), data, any, false).is_null() {
        return false;
    }
    true
}

/// `tree_link_nodes`: the certificate's policies linked into the tree.
fn link_nodes(tree: &mut Tree, curr: usize, cache: &PolicyCache) -> bool {
    cache
        .data
        .iter()
        .flatten()
        .all(|&d| link_matching_nodes(tree, curr, d))
}

/// `tree_add_unmatched`: a node under `n` for `id` (or `n`'s policy) with `anyPolicy`'s
/// qualifiers.
fn add_unmatched(
    tree: &mut Tree,
    curr: usize,
    cache: &PolicyCache,
    id: *const ASN1_OBJECT,
    n: *const Node,
) -> bool {
    let nd = node_data(n);
    let id = if id.is_null() {
        nd.valid_policy.cast_const()
    } else {
        id
    };
    // SAFETY: a live object.
    let Some(mut d) = (unsafe { data_new(None, id, nd.flags & CRITICAL != 0) }) else {
        return false;
    };
    // SAFETY: the cache's `anyPolicy` (there is one when its level doesn't inhibit it).
    d.qualifier_set =
        unsafe { cache.any_policy.as_ref() }.map_or(ptr::null_mut(), |a| a.qualifier_set);
    d.flags |= SHARED_QUALIFIERS;
    let d = Box::into_raw(d);
    if tree.add_node(Some(curr), d, n, true).is_null() {
        // SAFETY: made above, not taken.
        drop(unsafe { Box::from_raw(d) });
        return false;
    }
    true
}

/// `tree_link_unmatched`: for a node of the level above without (all its expected) children,
/// nodes through `anyPolicy`.
fn link_unmatched(tree: &mut Tree, curr: usize, cache: &PolicyCache, n: *const Node) -> bool {
    let Some(last) = curr.checked_sub(1).and_then(|i| tree.level(i)) else {
        return false;
    };
    let nd = node_data(n);
    // SAFETY: the level's node.
    let nchild = unsafe { node(n) }.nchild.get();
    if last.flags & vflag(X509_V_FLAG_INHIBIT_MAP) != 0 || nd.flags & MAPPED == 0 {
        if nchild != 0 {
            return true;
        }
        return add_unmatched(tree, curr, cache, ptr::null(), n);
    }
    let expected = &nd.expected_policy_set;
    if usize::try_from(nchild).is_ok_and(|c| c == expected.len()) {
        return true;
    }
    for &oid in expected {
        if tree.level(curr).is_some_and(|l| level_find_node(l, n, oid)) {
            continue;
        }
        if !add_unmatched(tree, curr, cache, oid, n) {
            return false;
        }
    }
    true
}

/// `tree_link_any`: the level above's nodes linked through `anyPolicy`, and `anyPolicy`'s.
fn link_any(tree: &mut Tree, curr: usize, cache: &PolicyCache) -> bool {
    let Some((nodes, any)) = curr
        .checked_sub(1)
        .and_then(|i| tree.level(i))
        .map(|l| (l.nodes.clone(), l.any_policy))
    else {
        return false;
    };
    if !nodes
        .into_iter()
        .all(|n| link_unmatched(tree, curr, cache, n))
    {
        return false;
    }
    !(!any.is_null()
        && tree
            .add_node(Some(curr), cache.any_policy, any, false)
            .is_null())
}

/// `tree_prune`: drops the current level's mapped nodes when mapping is inhibited, then the
/// childless nodes of each level above: `X509_PCY_TREE_EMPTY` if nothing is left.
fn prune(tree: &mut Tree, curr: usize) -> c_int {
    let Some(l) = tree.level_mut(curr) else {
        return X509_PCY_TREE_INTERNAL;
    };
    if l.flags & vflag(X509_V_FLAG_INHIBIT_MAP) != 0 {
        l.nodes.retain(|&n| {
            let mapped = node_data(n).flags & MAP_MASK != 0;
            if mapped {
                // SAFETY: the level's node.
                adopt(unsafe { node(n) }.parent, -1);
            }
            !mapped
        });
    }
    for c in (0..curr).rev() {
        let Some(l) = tree.level_mut(c) else {
            return X509_PCY_TREE_INTERNAL;
        };
        l.nodes.retain(|&n| {
            // SAFETY: the level's node.
            let nd = unsafe { node(n) };
            let childless = nd.nchild.get() == 0;
            if childless {
                adopt(nd.parent, -1);
            }
            !childless
        });
        // SAFETY: the level's node, or NULL.
        if let Some(a) = unsafe { l.any_policy.as_ref() }
            && a.nchild.get() == 0
        {
            adopt(a.parent, -1);
            l.any_policy = ptr::null_mut();
        }
        if c == 0 && l.any_policy.is_null() {
            return X509_PCY_TREE_EMPTY;
        }
    }
    X509_PCY_TREE_VALID
}

/// `node_cmp`: nodes in the order of their policies.
unsafe extern "C" fn node_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's slots, holding nodes.
    let a = unsafe { *a.cast::<*const Node>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const Node>() };
    // SAFETY: as above.
    unsafe { OBJ_cmp(node_data(a).valid_policy, node_data(b).valid_policy) }
}

/// `tree_add_auth_node`: adds the node (unless one for its policy is there) to the list, made
/// if NULL.
fn add_auth_node(nodes: &mut *mut OPENSSL_STACK, n: *mut Node) -> bool {
    if nodes.is_null() {
        // SAFETY: a comparator.
        *nodes = unsafe { OPENSSL_sk_new(Some(node_cmp)) };
        if nodes.is_null() {
            return false;
        }
    }
    // SAFETY: the list; a node.
    if unsafe { OPENSSL_sk_find(*nodes, n.cast()) } >= 0 {
        return true;
    }
    // SAFETY: as above.
    unsafe { OPENSSL_sk_push(*nodes, n.cast()) != 0 }
}

/// `tree_calculate_authority_set`'s results: failed, the tree's own list, or a list to free.
const CALC_FAILURE: c_int = 0;
const CALC_OK_NOFREE: c_int = 1;
const CALC_OK_DOFREE: c_int = 2;

/// `tree_calculate_authority_set`: the nodes whose parents are `anyPolicy` down the levels
/// that have it: the tree's authority policies, or (when the last level has `anyPolicy`, which
/// is then the authority set) a list of their own.
fn calculate_authority_set(tree: &mut Tree, pnodes: &mut *mut OPENSSL_STACK) -> c_int {
    let Some(last_any) = tree.levels.last().map(|l| l.any_policy) else {
        return CALC_FAILURE;
    };
    let to_pnodes = !last_any.is_null();
    if to_pnodes && !add_auth_node(&mut tree.auth_policies, last_any) {
        return CALC_FAILURE;
    }
    let mut c = 0;
    for _ in 1..tree.levels.len() {
        let Some(anyptr) = tree.level(c).map(|l| l.any_policy) else {
            break;
        };
        if anyptr.is_null() {
            break;
        }
        c += 1;
        let nodes = tree.level(c).map(|l| l.nodes.clone()).unwrap_or_default();
        for n in nodes {
            // SAFETY: the level's node.
            if !ptr::eq(unsafe { node(n) }.parent, anyptr) {
                continue;
            }
            let target = if to_pnodes {
                &mut *pnodes
            } else {
                &mut tree.auth_policies
            };
            if !add_auth_node(target, n) {
                if to_pnodes {
                    // SAFETY: the list made here.
                    unsafe { OPENSSL_sk_free(*pnodes) };
                    *pnodes = ptr::null_mut();
                }
                return CALC_FAILURE;
            }
        }
    }
    if to_pnodes {
        return CALC_OK_DOFREE;
    }
    *pnodes = tree.auth_policies;
    CALC_OK_NOFREE
}

/// `tree_calculate_user_set`: the user policies: the authority set's nodes for the policies
/// asked for, or nodes made under the last level's `anyPolicy`'s parent; all of them if
/// `anyPolicy` is asked for.
///
/// # Safety
/// `policy_oids` is NULL or a live list of live objects; `auth_nodes` is NULL or a live list
/// of the tree's nodes.
unsafe fn calculate_user_set(
    tree: &mut Tree,
    policy_oids: *mut stack_st_ASN1_OBJECT,
    auth_nodes: *mut OPENSSL_STACK,
) -> bool {
    // SAFETY: the caller's list.
    let n = unsafe { OPENSSL_sk_num(policy_oids.cast()) };
    if n <= 0 {
        return true;
    }
    let oid = |i| {
        // SAFETY: an index within the list.
        unsafe { OPENSSL_sk_value(policy_oids.cast(), i) }.cast::<ASN1_OBJECT>()
    };
    let any = tree.levels.last().map_or(ptr::null_mut(), |l| l.any_policy);
    if (0..n).any(|i| is_any(oid(i))) {
        tree.flags |= ANY_POLICY;
        return true;
    }
    for i in 0..n {
        let o = oid(i);
        // `ossl_policy_tree_find_sk`, its policies being distinct.
        // SAFETY: the caller's list.
        let found = (0..unsafe { OPENSSL_sk_num(auth_nodes) })
            // SAFETY: an index within it.
            .map(|k| unsafe { OPENSSL_sk_value(auth_nodes, k) }.cast::<Node>())
            .find(|&n| same(node_data(n).valid_policy, o));
        let n = match found {
            Some(n) => n,
            None => {
                if any.is_null() {
                    continue;
                }
                let ad = node_data(any);
                // SAFETY: the caller's object.
                let Some(mut extra) = (unsafe { data_new(None, o, ad.flags & CRITICAL != 0) })
                else {
                    return false;
                };
                extra.qualifier_set = ad.qualifier_set;
                extra.flags = SHARED_QUALIFIERS | EXTRA_NODE;
                let extra = Box::into_raw(extra);
                // SAFETY: the tree's node.
                let parent = unsafe { node(any) }.parent;
                let n = tree.add_node(None, extra, parent, true);
                if n.is_null() {
                    // SAFETY: made above, not taken.
                    drop(unsafe { Box::from_raw(extra) });
                    return false;
                }
                n
            }
        };
        if tree.user_policies.is_null() {
            // SAFETY: no preconditions.
            tree.user_policies = unsafe { OPENSSL_sk_new_null() };
            if tree.user_policies.is_null() {
                return false;
            }
        }
        // SAFETY: the tree's list; its node.
        if unsafe { OPENSSL_sk_push(tree.user_policies, n.cast()) } == 0 {
            return false;
        }
    }
    true
}

/// `tree_evaluate`: grows and prunes the tree level by level.
fn evaluate(tree: &mut Tree) -> c_int {
    for curr in 1..tree.levels.len() {
        let Some((cert, flags)) = tree.level(curr).map(|l| (l.cert, l.flags)) else {
            return X509_PCY_TREE_INTERNAL;
        };
        // SAFETY: the level's certificate, which it holds a reference to.
        let Some(cache) = (unsafe { cache_of(cert) }) else {
            return X509_PCY_TREE_INTERNAL;
        };
        if !link_nodes(tree, curr, cache) {
            return X509_PCY_TREE_INTERNAL;
        }
        if flags & vflag(X509_V_FLAG_INHIBIT_ANY) == 0 && !link_any(tree, curr, cache) {
            return X509_PCY_TREE_INTERNAL;
        }
        let ret = prune(tree, curr);
        if ret != X509_PCY_TREE_VALID {
            return ret;
        }
    }
    X509_PCY_TREE_VALID
}

/// The tree behind a pointer.
///
/// # Safety
/// `tree` is NULL or a live tree.
unsafe fn tree_of<'a>(tree: *const X509_POLICY_TREE) -> Option<&'a Tree> {
    // SAFETY: the caller's guarantee; a tree is a `Tree`.
    unsafe { tree.cast::<Tree>().as_ref() }
}

/// The level behind a pointer.
///
/// # Safety
/// `level` is NULL or a live tree's level.
unsafe fn level_of<'a>(level: *const X509_POLICY_LEVEL) -> Option<&'a Level> {
    // SAFETY: the caller's guarantee; a level is a `Level`.
    unsafe { level.cast::<Level>().as_ref() }
}

/// The node behind a pointer.
///
/// # Safety
/// `n` is NULL or a live tree's node.
unsafe fn node_of<'a>(n: *const X509_POLICY_NODE) -> Option<&'a Node> {
    // SAFETY: the caller's guarantee; a node is a `Node`.
    unsafe { n.cast::<Node>().as_ref() }
}

/// The user policies (`X509_policy_tree_get0_user_policies`).
fn user_policies(t: &Tree) -> *mut OPENSSL_STACK {
    if t.flags & ANY_POLICY != 0 {
        t.auth_policies
    } else {
        t.user_policies
    }
}

ffi_export! {
    /// Builds the policy tree of `certs` (the leaf first, the trust anchor last), with the
    /// policies the caller accepts and the `X509_V_FLAG_*` policy flags:
    /// `X509_PCY_TREE_VALID` (the tree, or NULL for none, in `*ptree`),
    /// `X509_PCY_TREE_FAILURE` (an explicit policy is required, and none is acceptable),
    /// `X509_PCY_TREE_INVALID` (invalid policy extensions), or `X509_PCY_TREE_INTERNAL`.
    /// `*pexplicit_policy` is whether an explicit policy is required. NULL outputs, which
    /// OpenSSL writes through, give `X509_PCY_TREE_INTERNAL` (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ptree` and `pexplicit_policy` are NULL or writable; `certs` is NULL or a live list of
    /// live certificates; `policy_oids` is NULL or a live list of live objects.
    pub unsafe extern "C" fn X509_policy_check(ptree: *mut *mut X509_POLICY_TREE, pexplicit_policy: *mut c_int, certs: *mut stack_st_X509, policy_oids: *mut stack_st_ASN1_OBJECT, flags: c_uint) -> c_int
    where failure = X509_PCY_TREE_INTERNAL, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let (Some(ptree), Some(pexplicit)) = (unsafe { ptree.as_mut() }, unsafe { pexplicit_policy.as_mut() }) else {
            return X509_PCY_TREE_INTERNAL;
        };
        *ptree = ptr::null_mut();
        *pexplicit = 0;
        // SAFETY: the caller's list.
        let (init_ret, tree) = unsafe { tree_init(certs, flags) };
        if init_ret <= 0 {
            return init_ret;
        }
        let explicit = init_ret & X509_PCY_TREE_EXPLICIT != 0;
        if explicit {
            *pexplicit = 1;
        }
        if init_ret & X509_PCY_TREE_EMPTY != 0 {
            return if explicit { X509_PCY_TREE_FAILURE } else { X509_PCY_TREE_VALID };
        }
        let Some(mut tree) = tree else { return X509_PCY_TREE_INTERNAL };
        let ret = evaluate(&mut tree);
        if ret <= 0 {
            return X509_PCY_TREE_INTERNAL;
        }
        if ret == X509_PCY_TREE_EMPTY {
            return if explicit { X509_PCY_TREE_FAILURE } else { X509_PCY_TREE_VALID };
        }
        let mut auth_nodes = ptr::null_mut();
        let calc = calculate_authority_set(&mut tree, &mut auth_nodes);
        if calc == CALC_FAILURE {
            return X509_PCY_TREE_INTERNAL;
        }
        // SAFETY: the list (with the nodes' comparator), or NULL.
        unsafe { OPENSSL_sk_sort(auth_nodes) };
        // SAFETY: the caller's list; the authority set.
        let ok = unsafe { calculate_user_set(&mut tree, policy_oids, auth_nodes) };
        if calc == CALC_OK_DOFREE {
            // SAFETY: the list made for the calculation.
            unsafe { OPENSSL_sk_free(auth_nodes) };
        }
        if !ok {
            return X509_PCY_TREE_INTERNAL;
        }
        // SAFETY: the tree's list, or NULL.
        if explicit && unsafe { OPENSSL_sk_num(user_policies(&tree)) } <= 0 {
            return X509_PCY_TREE_FAILURE;
        }
        *ptree = Box::into_raw(tree).cast();
        X509_PCY_TREE_VALID
    }
}

ffi_export! {
    /// Frees the tree (nothing for NULL).
    ///
    /// # Safety
    /// `tree` is NULL or a tree from `X509_policy_check`, not used after.
    pub unsafe extern "C" fn X509_policy_tree_free(tree: *mut X509_POLICY_TREE)
    where failure = (), library = ERR_LIB_X509
    {
        if !tree.is_null() {
            // SAFETY: the caller's guarantee; made by `Box::into_raw`.
            drop(unsafe { Box::from_raw(tree.cast::<Tree>()) });
        }
    }
}

ffi_export! {
    /// The number of the tree's levels (0 for NULL).
    ///
    /// # Safety
    /// `tree` is NULL or a live tree.
    pub unsafe extern "C" fn X509_policy_tree_level_count(tree: *const X509_POLICY_TREE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { tree_of(tree) }.map_or(0, |t| c_int::try_from(t.levels.len()).unwrap_or(0))
    }
}

ffi_export! {
    /// The tree's level `i` (the trust anchor's 0), or NULL.
    ///
    /// # Safety
    /// `tree` is NULL or a live tree.
    pub unsafe extern "C" fn X509_policy_tree_get0_level(tree: *const X509_POLICY_TREE, i: c_int) -> *mut X509_POLICY_LEVEL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let level = unsafe { tree_of(tree) }.and_then(|t| t.levels.get(usize::try_from(i).ok()?));
        level.map_or(ptr::null_mut(), |l| ptr::from_ref(l).cast_mut().cast())
    }
}

ffi_export! {
    /// The tree's authority policies, or NULL.
    ///
    /// # Safety
    /// `tree` is NULL or a live tree.
    pub unsafe extern "C" fn X509_policy_tree_get0_policies(tree: *const X509_POLICY_TREE) -> *mut stack_st_X509_POLICY_NODE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { tree_of(tree) }.map_or(ptr::null_mut(), |t| t.auth_policies.cast())
    }
}

ffi_export! {
    /// The tree's user policies (the authority policies if `anyPolicy` was asked for), or
    /// NULL.
    ///
    /// # Safety
    /// `tree` is NULL or a live tree.
    pub unsafe extern "C" fn X509_policy_tree_get0_user_policies(tree: *const X509_POLICY_TREE) -> *mut stack_st_X509_POLICY_NODE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { tree_of(tree) }.map_or(ptr::null_mut(), |t| user_policies(t).cast())
    }
}

ffi_export! {
    /// The number of the level's nodes, `anyPolicy`'s included (0 for NULL).
    ///
    /// # Safety
    /// `level` is NULL or a live tree's level.
    pub unsafe extern "C" fn X509_policy_level_node_count(level: *mut X509_POLICY_LEVEL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { level_of(level) }) else { return 0 };
        let n = l.nodes.len() + usize::from(!l.any_policy.is_null());
        c_int::try_from(n).unwrap_or(c_int::MAX)
    }
}

ffi_export! {
    /// The level's node `i` (`anyPolicy`'s first, if any), or NULL.
    ///
    /// # Safety
    /// `level` is NULL or a live tree's level.
    pub unsafe extern "C" fn X509_policy_level_get0_node(level: *const X509_POLICY_LEVEL, i: c_int) -> *mut X509_POLICY_NODE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { level_of(level) }) else { return ptr::null_mut() };
        let mut i = i;
        if !l.any_policy.is_null() {
            if i == 0 {
                return l.any_policy.cast();
            }
            i -= 1;
        }
        usize::try_from(i).ok().and_then(|i| l.nodes.get(i)).map_or(ptr::null_mut(), |&n| n.cast())
    }
}

ffi_export! {
    /// The node's policy, or NULL.
    ///
    /// # Safety
    /// `node` is NULL or a live tree's node.
    pub unsafe extern "C" fn X509_policy_node_get0_policy(node: *const X509_POLICY_NODE) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { node_of(node) }.map_or(ptr::null(), |n| {
            // SAFETY: the node's policy.
            unsafe { data(n.data) }.valid_policy.cast_const()
        })
    }
}

ffi_export! {
    /// The node's policy's qualifiers, or NULL.
    ///
    /// # Safety
    /// `node` is NULL or a live tree's node.
    pub unsafe extern "C" fn X509_policy_node_get0_qualifiers(node: *const X509_POLICY_NODE) -> *mut stack_st_POLICYQUALINFO
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { node_of(node) }.map_or(ptr::null_mut(), |n| {
            // SAFETY: the node's policy.
            unsafe { data(n.data) }.qualifier_set
        })
    }
}

ffi_export! {
    /// The node's parent (NULL for the trust anchor's, and for NULL).
    ///
    /// # Safety
    /// `node` is NULL or a live tree's node.
    pub unsafe extern "C" fn X509_policy_node_get0_parent(node: *const X509_POLICY_NODE) -> *const X509_POLICY_NODE
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { node_of(node) }.map_or(ptr::null(), |n| n.parent.cast())
    }
}

ffi_export! {
    /// Prints the node at `indent`: its policy, whether critical, and its qualifiers. Nothing
    /// for a NULL node, which OpenSSL reads through (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` is a live BIO; `node` is NULL or a live tree's node.
    pub unsafe extern "C" fn X509_POLICY_NODE_print(out: *mut BIO, node: *mut X509_POLICY_NODE, indent: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { node_of(node) }) else { return };
        // SAFETY: the node's policy.
        let dat = unsafe { data(n.data) };
        let inner = indent.saturating_add(2);
        // SAFETY: the caller's BIO; a format with its arguments.
        unsafe { BIO_printf(out, c"%*sPolicy: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: as above; the policy's object.
        unsafe { i2a_ASN1_OBJECT(out, dat.valid_policy) };
        // SAFETY: as above.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
        let crit = if dat.flags & CRITICAL != 0 { c"Critical" } else { c"Non Critical" };
        // SAFETY: as above.
        unsafe { BIO_printf(out, c"%*s%s\n".as_ptr(), inner, c"".as_ptr(), crit.as_ptr()) };
        if dat.qualifier_set.is_null() {
            // SAFETY: as above.
            unsafe { BIO_printf(out, c"%*sNo Qualifiers\n".as_ptr(), inner, c"".as_ptr()) };
        } else {
            // SAFETY: as above; the policy's qualifiers.
            unsafe { print_qualifiers(out, dat.qualifier_set.cast(), inner) };
            // SAFETY: as above.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
    }
}

/// `check_policy`: the context's default policy check (after the chain's other checks, with
/// `X509_V_FLAG_POLICY_CHECK`): the policy tree of the chain (none for a CRL path's
/// context), each invalid policy extension or the lack of a required explicit policy going to
/// the callback, and with `X509_V_FLAG_NOTIFY_POLICY` a call (with 2) once it's built.
pub(crate) unsafe extern "C" fn check_policy(ctx: *mut X509_STORE_CTX) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "check_policy",
        || 0,
        // SAFETY: the context the verification is called with.
        move || unsafe { check_policy_inner(ctx) },
    )
}

/// [`check_policy`]'s body.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_policy_inner(ctx: *mut X509_STORE_CTX) -> c_int {
    const F: &str = "check_policy";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    if !c.parent.is_null() {
        return 1;
    }
    let bare = c.bare_ta_signed != 0;
    let chain = c.chain;
    // The bare trust anchor's place, as the anchor isn't in the tree.
    // SAFETY: the context's chain.
    if bare && unsafe { OPENSSL_sk_push(chain.cast(), ptr::null()) } == 0 {
        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
        c.error = X509_V_ERR_OUT_OF_MEM;
        return -1;
    }
    // SAFETY: a context's parameters are NULL or live, and its own.
    let (policies, flags) = unsafe { c.param.cast::<Param>().as_ref() }
        .map_or((ptr::null_mut(), 0), |p| (p.policies, p.flags));
    // The check's `unsigned int` flags, as C's conversion makes them.
    let pflags = c_uint::try_from(flags & c_ulong::from(c_uint::MAX)).unwrap_or(0);
    let mut tree = ptr::null_mut();
    let mut explicit = 0;
    // SAFETY: the outputs; the chain; the parameters' policies, or NULL.
    let ret =
        unsafe { X509_policy_check(&raw mut tree, &raw mut explicit, chain, policies, pflags) };
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    c.tree = tree;
    c.explicit_policy = explicit;
    if bare {
        // SAFETY: the chain, with the NULL pushed above.
        unsafe { OPENSSL_sk_pop(chain.cast()) };
    }
    if ret == X509_PCY_TREE_INTERNAL {
        err::raise(ERR_LIB_X509, ERR_R_X509_LIB, F);
        c.error = X509_V_ERR_OUT_OF_MEM;
        return -1;
    }
    let verify_cb = c.verify_cb;
    if ret == X509_PCY_TREE_INVALID {
        let mut cbcalled = false;
        // SAFETY: the chain.
        for i in 0..unsafe { OPENSSL_sk_num(chain.cast()) } {
            // SAFETY: an index within it.
            let x = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast::<X509>();
            // SAFETY: a certificate of the chain.
            let invalid = unsafe { cache_view(x) }.flags & ex(EXFLAG_INVALID_POLICY) != 0;
            if invalid {
                cbcalled = true;
                // SAFETY: the context; its certificate.
                if unsafe { verify_cb_cert(ctx, x, i, X509_V_ERR_INVALID_POLICY_EXTENSION) } == 0 {
                    return 0;
                }
            }
        }
        if !cbcalled {
            err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, F);
            return 0;
        }
        return 1;
    }
    if ret == X509_PCY_TREE_FAILURE {
        c.current_cert = ptr::null_mut();
        c.error = X509_V_ERR_NO_EXPLICIT_POLICY;
        // SAFETY: the context's callback, with no reference into it held.
        return verify_cb.map_or(0, |f| unsafe { f(0, ctx) });
    }
    if ret != X509_PCY_TREE_VALID {
        err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, F);
        return 0;
    }
    if flags & c_ulong::from(X509_V_FLAG_NOTIFY_POLICY.cast_unsigned()) != 0 {
        c.current_cert = ptr::null_mut();
        // SAFETY: as above.
        if verify_cb.map_or(0, |f| unsafe { f(2, ctx) }) == 0 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: `X509_policy_check` with NULL outputs, and `X509_POLICY_NODE_print`
    /// with a NULL node, which OpenSSL writes or reads through.
    #[test]
    fn null_arguments_are_refused() {
        let mut explicit = 0;
        // SAFETY: NULL where OpenSSL writes through it.
        let r = unsafe {
            X509_policy_check(
                ptr::null_mut(),
                &raw mut explicit,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(r, X509_PCY_TREE_INTERNAL);
        let mut tree = ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe {
            X509_policy_check(
                &raw mut tree,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(r, X509_PCY_TREE_INTERNAL);
        // SAFETY: NULL where OpenSSL reads through it; no BIO is touched.
        unsafe { X509_POLICY_NODE_print(ptr::null_mut(), ptr::null_mut(), 0) };
    }

    /// The tree's getters on NULL, as OpenSSL's.
    #[test]
    fn getters_take_null() {
        // SAFETY: NULL, which they accept.
        unsafe {
            assert_eq!(X509_policy_tree_level_count(ptr::null()), 0);
        }
        // SAFETY: as above.
        assert!(unsafe { X509_policy_tree_get0_level(ptr::null(), 0) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_policy_level_node_count(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_policy_node_get0_parent(ptr::null()) }.is_null());
    }
}
