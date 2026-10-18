//! Groups (`t1_lib.c`): the supported list (configured, or the 3.5 default), the key-share
//! groups and tuples, validity by version and security, the server's shared-group choice, and
//! TLS 1.2's EC checks. Group details come from the providers ([`GroupInfo`], their
//! `TLS-GROUP` capability).

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::security::{self, SecOther};
use super::version;
use crate::conn::Connection;
use crate::consts::group;
use crate::crypto::GroupInfo;

/// The default list (`TLS_DEFAULT_GROUP_LIST`):
/// `?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1 / ?ffdhe2048:?ffdhe3072`.
/// Each tuple's groups, and which get an initial key share.
const DEFAULT_TUPLES: [&[(u16, bool)]; 4] = [
    &[(group::X25519_MLKEM768, true)],
    &[(group::X25519, true), (group::SECP256R1, false)],
    &[
        (group::X448, false),
        (group::SECP384R1, false),
        (group::SECP521R1, false),
    ],
    &[(group::FFDHE2048, false), (group::FFDHE3072, false)],
];

/// Suite B's curves (`suiteb_curves`).
const SUITEB_CURVES: [u16; 2] = [group::SECP256R1, group::SECP384R1];

/// The legacy NID of each group OpenSSL knows (`nid_to_group`).
const NID_TO_GROUP: [(c_int, u16); 45] = [
    (abi::NID_sect163k1, group::SECT163K1),
    (abi::NID_sect163r1, group::SECT163R1),
    (abi::NID_sect163r2, group::SECT163R2),
    (abi::NID_sect193r1, group::SECT193R1),
    (abi::NID_sect193r2, group::SECT193R2),
    (abi::NID_sect233k1, group::SECT233K1),
    (abi::NID_sect233r1, group::SECT233R1),
    (abi::NID_sect239k1, group::SECT239K1),
    (abi::NID_sect283k1, group::SECT283K1),
    (abi::NID_sect283r1, group::SECT283R1),
    (abi::NID_sect409k1, group::SECT409K1),
    (abi::NID_sect409r1, group::SECT409R1),
    (abi::NID_sect571k1, group::SECT571K1),
    (abi::NID_sect571r1, group::SECT571R1),
    (abi::NID_secp160k1, group::SECP160K1),
    (abi::NID_secp160r1, group::SECP160R1),
    (abi::NID_secp160r2, group::SECP160R2),
    (abi::NID_secp192k1, group::SECP192K1),
    (abi::NID_X9_62_prime192v1, group::SECP192R1),
    (abi::NID_secp224k1, group::SECP224K1),
    (abi::NID_secp224r1, group::SECP224R1),
    (abi::NID_secp256k1, group::SECP256K1),
    (abi::NID_X9_62_prime256v1, group::SECP256R1),
    (abi::NID_secp384r1, group::SECP384R1),
    (abi::NID_secp521r1, group::SECP521R1),
    (abi::NID_brainpoolP256r1, group::BRAINPOOLP256R1),
    (abi::NID_brainpoolP384r1, group::BRAINPOOLP384R1),
    (abi::NID_brainpoolP512r1, group::BRAINPOOLP512R1),
    (abi::NID_X25519, group::X25519),
    (abi::NID_X448, group::X448),
    (abi::NID_brainpoolP256r1tls13, group::BRAINPOOLP256R1_TLS13),
    (abi::NID_brainpoolP384r1tls13, group::BRAINPOOLP384R1_TLS13),
    (abi::NID_brainpoolP512r1tls13, group::BRAINPOOLP512R1_TLS13),
    (abi::NID_id_tc26_gost_3410_2012_256_paramSetA, group::GC256A),
    (abi::NID_id_tc26_gost_3410_2012_256_paramSetB, group::GC256B),
    (abi::NID_id_tc26_gost_3410_2012_256_paramSetC, group::GC256C),
    (abi::NID_id_tc26_gost_3410_2012_256_paramSetD, group::GC256D),
    (abi::NID_id_tc26_gost_3410_2012_512_paramSetA, group::GC512A),
    (abi::NID_id_tc26_gost_3410_2012_512_paramSetB, group::GC512B),
    (abi::NID_id_tc26_gost_3410_2012_512_paramSetC, group::GC512C),
    (abi::NID_ffdhe2048, group::FFDHE2048),
    (abi::NID_ffdhe3072, group::FFDHE3072),
    (abi::NID_ffdhe4096, group::FFDHE4096),
    (abi::NID_ffdhe6144, group::FFDHE6144),
    (abi::NID_ffdhe8192, group::FFDHE8192),
];

/// `tls1_group_id2nid`: a group's legacy NID; with `include_unknown`, `TLSEXT_nid_unknown`
/// with the id for a group without one, else `NID_undef`.
#[must_use]
pub fn group_to_nid(id: u16, include_unknown: bool) -> c_int {
    if id == 0 {
        return abi::NID_undef;
    }
    if let Some(&(nid, _)) = NID_TO_GROUP.iter().find(|&&(_, g)| g == id) {
        return nid;
    }
    if include_unknown {
        abi::TLSEXT_nid_unknown | c_int::from(id)
    } else {
        abi::NID_undef
    }
}

/// `tls1_nid2group_id`: the group of a legacy NID, or 0.
#[must_use]
pub fn nid_to_group(nid: c_int) -> u16 {
    NID_TO_GROUP
        .iter()
        .find(|&&(n, _)| n == nid)
        .map_or(0, |&(_, g)| g)
}

/// The default group list for the groups the providers offer (`ssl_load_groups` setting
/// `TLS_DEFAULT_GROUP_LIST`): the groups in order, those that get an initial key share, and
/// where each tuple starts (unavailable groups and empty tuples dropped, as `?` does).
#[must_use]
pub fn default_list(available: &[GroupInfo]) -> (Vec<u16>, Vec<u16>, Vec<usize>) {
    let mut groups = Vec::new();
    let mut shares = Vec::new();
    let mut tuples = Vec::new();
    for t in DEFAULT_TUPLES {
        let start = groups.len();
        for &(g, share) in t {
            if available.iter().any(|a| a.id == g) {
                groups.push(g);
                if share {
                    shares.push(g);
                }
            }
        }
        if groups.len() > start {
            tuples.push(start);
        }
    }
    (groups, shares, tuples)
}

/// `tls1_group_id_lookup`: the providers' details of a group.
#[must_use]
pub fn lookup(c: &Connection, id: u16) -> Option<&GroupInfo> {
    c.hs.sh.groups.iter().find(|g| g.id == id)
}

/// `tls13_set_encoded_pub_key`'s checks of a TLS 1.3 key share before it is used: a DH share
/// must be padded to the prime's length (RFC 8446, section 4.2.8.1), which `own_len`, this
/// end's share in the group, has (as OpenSSL's encoding pads it); an EC share must be an
/// uncompressed point. Whether `peer` passes; a KEM's or an XDH group's octets go on to the
/// provider as they are.
#[must_use]
pub fn encoded_share_ok(info: &GroupInfo, peer: &[u8], own_len: usize) -> bool {
    match info.algorithm.as_str() {
        "DH" => own_len > 0 && peer.len() == own_len,
        "EC" => peer.len() >= 3 && peer.first() == Some(&4),
        _ => true,
    }
}

/// `tls1_get_supported_groups`: Suite B's curves in a Suite B mode, otherwise the configured
/// list (or the default).
#[must_use]
pub fn supported(c: &Connection) -> Vec<u16> {
    let sb = version::suiteb(c);
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_128_LOS).unwrap_or(0) {
        return SUITEB_CURVES.to_vec();
    }
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_128_LOS_ONLY).unwrap_or(0) {
        return SUITEB_CURVES.get(..1).unwrap_or_default().to_vec();
    }
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_192_LOS).unwrap_or(0) {
        return SUITEB_CURVES.get(1..).unwrap_or_default().to_vec();
    }
    if c.cfg.no_groups {
        return Vec::new();
    }
    if c.cfg.groups.is_empty() {
        return default_list(&c.hs.sh.groups).0;
    }
    c.cfg.groups.clone()
}

/// `tls1_get_requested_keyshare_groups`: the groups the first ClientHello sends key shares
/// for, in the configured (or default) order.
#[must_use]
pub fn keyshare_groups(c: &Connection) -> Vec<u16> {
    if c.cfg.no_groups {
        return Vec::new();
    }
    if c.cfg.groups.is_empty() {
        return default_list(&c.hs.sh.groups).1;
    }
    c.cfg.key_share_groups.clone()
}

/// `tls1_get_group_tuples`: where each preference tuple starts in [`supported`]'s list.
#[must_use]
pub fn tuples(c: &Connection) -> Vec<usize> {
    if c.cfg.no_groups {
        return Vec::new();
    }
    if c.cfg.groups.is_empty() {
        return default_list(&c.hs.sh.groups).2;
    }
    if c.cfg.group_tuples.is_empty() {
        // A legacy list (no tuple syntax): one tuple of everything.
        return vec![0];
    }
    c.cfg.group_tuples.clone()
}

/// `tls_valid_group`: whether group `id` may be used with versions `min..=max` (and, with
/// `isec`, whether it is a TLS 1.2 ECDHE group); and whether it is fit for TLS 1.3.
#[must_use]
pub fn valid(c: &Connection, id: u16, min: u16, max: u16, isec: bool) -> (bool, bool) {
    let Some(g) = lookup(c, id) else {
        return (false, false);
    };
    let (gmin, gmax) = if c.cfg.dtls {
        (g.min_dtls, g.max_dtls)
    } else {
        (g.min_tls, g.max_tls)
    };
    if gmin < 0 || gmax < 0 {
        return (false, false);
    }
    let vc = super::ciphers::vcmp;
    let mut ok = gmax == 0 || vc(i32::from(min), gmax).is_le();
    if gmin > 0 {
        ok &= vc(i32::from(max), gmin).is_ge();
    }
    let ok13 = !c.cfg.dtls
        && ok
        && max == version::of(abi::TLS1_3_VERSION)
        && (gmax == 0 || gmax >= abi::TLS1_3_VERSION);
    ok &= !isec || g.algorithm == "EC" || g.algorithm == "X25519" || g.algorithm == "X448";
    (ok, ok13)
}

/// `tls_group_allowed`: whether the security level (or callback) allows group `id` for `op`.
#[must_use]
pub fn allowed(c: &Connection, id: u16, op: c_int) -> bool {
    let Some(g) = lookup(c, id) else {
        return false;
    };
    let bits = c_int::try_from(g.security_bits).unwrap_or(c_int::MAX);
    security::check(
        c,
        op,
        bits,
        group_to_nid(id, false),
        SecOther::CodePoint(id.to_be_bytes()),
    )
}

/// `check_in_list`: where `id` is in `list` (and, with `check_allow`, allowed by
/// `SSL_SECOP_CURVE_CHECK`).
#[must_use]
pub fn check_in_list(c: &Connection, id: u16, list: &[u16], check_allow: bool) -> Option<usize> {
    list.iter()
        .position(|&g| g == id && (!check_allow || allowed(c, g, abi::SSL_SECOP_CURVE_CHECK)))
}

/// `tls1_shared_group`: for `nmatch >= 0` the `nmatch`th shared group (0 if none), for -1 the
/// number shared, for -2 the group for a TLS 1.2 key exchange (Suite B's curve for its
/// suites, else the first shared). Servers only. With `SSL_OP_CIPHER_SERVER_PREFERENCE` this
/// end's order wins, otherwise the client's.
#[must_use]
pub fn shared_group(c: &Connection, nmatch: i32) -> u16 {
    if !c.cfg.server {
        return 0;
    }
    let mut nmatch = nmatch;
    if nmatch == -2 {
        if version::suiteb(c) != 0 {
            let cid = c.hs.new_cipher.map_or(0, |x| x.id);
            if cid == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
                return group::SECP256R1;
            }
            if cid == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
                return group::SECP384R1;
            }
            return 0;
        }
        nmatch = 0;
    }
    let ours = supported(c);
    let peer = &c.neg.peer_groups;
    let (pref, supp): (&[u16], &[u16]) =
        if c.cfg.options & abi::SSL_OP_CIPHER_SERVER_PREFERENCE != 0 {
            (&ours, peer)
        } else {
            (peer, &ours)
        };
    let mut k = 0i32;
    for &id in pref {
        if !supp.contains(&id) || !allowed(c, id, abi::SSL_SECOP_CURVE_SHARED) {
            continue;
        }
        let Some(g) = lookup(c, id) else {
            return 0;
        };
        let (gmin, gmax) = if c.cfg.dtls {
            (g.min_dtls, g.max_dtls)
        } else {
            (g.min_tls, g.max_tls)
        };
        if gmax == -1 {
            continue;
        }
        let v = i32::from(c.neg.version);
        let vc = super::ciphers::vcmp;
        if (gmin != 0 && vc(v, gmin).is_lt()) || (gmax != 0 && vc(v, gmax).is_gt()) {
            continue;
        }
        if nmatch == k {
            return id;
        }
        k = k.saturating_add(1);
    }
    if nmatch == -1 {
        return u16::try_from(k).unwrap_or(u16::MAX);
    }
    0
}

/// `tls1_check_group_id`: whether group `id` (an EC key's curve, or a TLS 1.2 key exchange's
/// group) is acceptable: Suite B's rule, this end's list (with `check_own`), the security
/// level, and (servers) the client's list, if it sent one.
#[must_use]
pub fn check_group_id(c: &Connection, id: u16, check_own: bool) -> bool {
    if id == 0 {
        return false;
    }
    if version::suiteb(c) != 0
        && let Some(nc) = c.hs.new_cipher
    {
        let want = if nc.id == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        {
            group::SECP256R1
        } else if nc.id == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
            group::SECP384R1
        } else {
            return false;
        };
        if id != want {
            return false;
        }
    }
    if check_own && !supported(c).contains(&id) {
        return false;
    }
    if !allowed(c, id, abi::SSL_SECOP_CURVE_CHECK) {
        return false;
    }
    if !c.cfg.server {
        return true;
    }
    let peer = &c.neg.peer_groups;
    peer.is_empty() || peer.contains(&id)
}

/// `tls1_check_ec_tmp_key`: whether a TLS 1.2 ECDHE suite `cid` has a group to use.
#[must_use]
pub fn check_ec_tmp_key(c: &Connection, cid: u32) -> bool {
    if version::suiteb(c) == 0 {
        return shared_group(c, 0) != 0;
    }
    if cid == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
        return check_group_id(c, group::SECP256R1, true);
    }
    if cid == crate::suites::cid(abi::TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
        return check_group_id(c, group::SECP384R1, true);
    }
    false
}

/// `tls1_get_formatlist`: the EC point formats sent (uncompressed and both compressed forms;
/// Suite B leaves out char2).
#[must_use]
pub fn formats(c: &Connection) -> Vec<u8> {
    let all = [
        crate::conn::statem::msgs_type(abi::TLSEXT_ECPOINTFORMAT_uncompressed),
        crate::conn::statem::msgs_type(abi::TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime),
        crate::conn::statem::msgs_type(abi::TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2),
    ];
    if version::suiteb(c) != 0 {
        all.get(..2).unwrap_or_default().to_vec()
    } else {
        all.to_vec()
    }
}

/// The groups a ClientHello may offer for versions `min..=max`, in order: valid and allowed
/// (`tls_construct_ctos_supported_groups`'s filter), with whether any is fit for TLS 1.3.
#[must_use]
pub fn offerable(c: &Connection, min: u16, max: u16) -> (Vec<u16>, bool) {
    let mut out = Vec::new();
    let mut any13 = false;
    for g in supported(c) {
        let (ok, ok13) = valid(c, g, min, max, false);
        if ok && allowed(c, g, abi::SSL_SECOP_CURVE_SUPPORTED) {
            any13 |= ok13;
            out.push(g);
        }
    }
    (out, any13)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testprov::keys;

    #[test]
    fn the_default_list_follows_its_tuples() {
        let (g, s, t) = default_list(&keys::groups());
        assert_eq!(
            g,
            [
                group::X25519_MLKEM768,
                group::X25519,
                group::SECP256R1,
                group::X448,
                group::SECP384R1,
                group::SECP521R1,
                group::FFDHE2048,
                group::FFDHE3072
            ]
        );
        assert_eq!(s, [group::X25519_MLKEM768, group::X25519]);
        assert_eq!(t, [0, 1, 3, 6]);
        // Unavailable groups drop out, and their tuples with them.
        let some: Vec<_> = keys::groups()
            .into_iter()
            .filter(|x| x.id != group::X25519_MLKEM768 && x.id != group::X448)
            .collect();
        let (g, s, t) = default_list(&some);
        assert_eq!(g.first(), Some(&group::X25519));
        assert_eq!(s, [group::X25519]);
        assert_eq!(t, [0, 2, 4]);
    }

    #[test]
    fn nids_map_both_ways() {
        assert_eq!(nid_to_group(abi::NID_X9_62_prime256v1), group::SECP256R1);
        assert_eq!(group_to_nid(group::X25519, false), abi::NID_X25519);
        assert_eq!(group_to_nid(group::X25519_MLKEM768, false), abi::NID_undef);
        assert_eq!(
            group_to_nid(group::X25519_MLKEM768, true),
            abi::TLSEXT_nid_unknown | 0x11ec
        );
    }
}
