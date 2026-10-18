//! Key changes: TLS 1.3's secrets and traffic keys (`tls13_enc.c`) and TLS 1.0–1.2's master
//! secret and key block (`t1_enc.c`), installed into the record layer at OpenSSL's points,
//! with the key log lines and the exporter secrets.

use core::ffi::c_int;

use rustyssl_abi as abi;

use crate::conn::{Connection, Event};
use crate::crypto::{HashAlg, Provider, Secret};
use crate::error::{Error, InFunc, Result};
use crate::keysched::{self, KeyBlock, PrfHash, Schedule13, keylog};
use crate::record::{Mode, Protection};
use crate::suites::{self, Cipher};

/// The key schedule's state across a handshake (`s->early_secret`, `handshake_secret`,
/// `master_secret`, the traffic secrets and hashes, and TLS 1.2's key block).
#[derive(Default)]
pub struct State {
    /// TLS 1.3's schedule, at its current stage.
    pub schedule: Option<Schedule13>,
    /// The handshake hash after the ServerHello (`handshake_traffic_hash`), kept for the
    /// client-write/server-read handshake keys when early data delays them.
    pub handshake_traffic_hash: Vec<u8>,
    /// The handshake hash up to the server's Finished (`server_finished_hash`).
    pub server_finished_hash: Vec<u8>,
    /// The handshake traffic secrets, which are also the Finished base keys
    /// (`client_finished_secret`, `server_finished_secret` hold the derived Finished keys in
    /// OpenSSL; here the base keys are kept and the Finished key derived when needed).
    pub client_hs_secret: Secret,
    /// See `client_hs_secret`.
    pub server_hs_secret: Secret,
    /// The current application traffic secrets (`client_app_traffic_secret`, ...), updated by
    /// KeyUpdate.
    pub client_app_secret: Secret,
    /// See `client_app_secret`.
    pub server_app_secret: Secret,
    /// The resumption master secret.
    pub resumption_master: Secret,
    /// The early secret for an external PSK the client keeps aside (`sess->early_secret`).
    pub psk_early: Option<Schedule13>,
    /// TLS 1.2's premaster secret, until the master secret is made.
    pub pms: Option<Secret>,
    /// TLS 1.2's key block, once made.
    pub key_block: Option<KeyBlock>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("keys::State")
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

/// `ssl_get_algorithm2`'s hashes: the handshake (transcript) hash and the PRF, with TLS 1.2
/// replacing the default MD5+SHA-1 by SHA-256.
#[must_use]
pub fn hashes(version: u16, cp: &Cipher) -> (HashAlg, PrfHash) {
    if version < crate::conn::common::version::of(abi::TLS1_2_VERSION) {
        return (HashAlg::Md5Sha1, PrfHash::Md5Sha1);
    }
    let hs = match cp.handshake_hash() {
        None | Some(HashAlg::Md5Sha1) => HashAlg::Sha256,
        Some(h) => h,
    };
    let prf = match cp.prf_hash() {
        Some(HashAlg::Sha384) => PrfHash::Sha384,
        _ => PrfHash::Sha256,
    };
    (hs, prf)
}

/// `ssl_handshake_md`: the transcript hash of the negotiated suite.
///
/// # Errors
/// No suite yet.
pub fn handshake_md(c: &Connection) -> Result<HashAlg> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    Ok(hashes(c.neg.version, cp).0)
}

/// `ssl_log_secret`: a key log line, when the callback is set.
pub fn log_secret(c: &mut Connection, label: &str, secret: &[u8]) {
    if c.cfg.callbacks.keylog {
        let line = keylog::line(label, &c.hs.client_random, secret);
        c.notify(Event::Keylog(line));
    }
}

/// The record layer's protection for a TLS 1.3 suite and traffic secret
/// (`derive_secret_key_and_iv` and `ssl_set_new_record_layer`).
fn protection13(p: &dyn Provider, cp: &Cipher, hash: HashAlg, secret: &[u8]) -> Result<Protection> {
    match cp.protection() {
        suites::Protection::Aead(alg) => {
            let k = keysched::traffic_keys(p, hash, secret, alg.key_len(), 12)?;
            Protection::tls13(p, alg, k.key.bytes(), k.iv.bytes())
        }
        suites::Protection::Null { mac } => {
            let n = mac.len();
            let k = keysched::traffic_keys(p, hash, secret, n, n)?;
            Ok(Protection::Tls13Integrity {
                hash: mac,
                key: k.key,
                iv: k.iv,
            })
        }
        _ => Err(Error::internal()),
    }
}

/// Checks that no handshake data waits under the old read keys (`SSL_R_NOT_ON_RECORD_BOUNDARY`).
fn check_boundary(c: &Connection) -> Result<()> {
    if c.hs_in.is_empty() {
        Ok(())
    } else {
        Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
        ))
    }
}

/// Installs TLS 1.3 protection in one direction.
fn install13(c: &mut Connection, read: bool, prot: Protection) -> Result<()> {
    if read {
        check_boundary(c)?;
        c.rr.set_protection(Mode::Tls13, prot);
        c.early_read = None;
    } else {
        c.rw.set_protection(Mode::Tls13, prot);
    }
    Ok(())
}

/// `tls13_generate_secret` for the early stage: the early secret from `psk` (or zeros) with
/// the transcript hash of `cp` (`tls13_generate_early_secret`, and the binder path).
///
/// # Errors
/// The provider failed.
pub fn generate_early(
    c: &mut Connection,
    p: &dyn Provider,
    cp: &Cipher,
    psk: Option<&[u8]>,
) -> Result<()> {
    let hash = hashes(
        c.neg
            .version
            .max(crate::conn::common::version::of(abi::TLS1_3_VERSION)),
        cp,
    )
    .0;
    c.hs.sh.keys.schedule = Some(Schedule13::new(p, hash, psk)?);
    Ok(())
}

/// `tls13_generate_handshake_secret`: the handshake secret from the shared secret (none for a
/// PSK-only resumption), starting from the early secret (or a zero PSK's).
///
/// # Errors
/// The provider failed, or no suite was chosen.
pub fn generate_handshake_secret(
    c: &mut Connection,
    p: &dyn Provider,
    shared: Option<&[u8]>,
) -> Result<()> {
    generate_handshake_secret_inner(c, p, shared).in_func("tls13_generate_handshake_secret")
}

/// See [`generate_handshake_secret`].
fn generate_handshake_secret_inner(
    c: &mut Connection,
    p: &dyn Provider,
    shared: Option<&[u8]>,
) -> Result<()> {
    let hash = handshake_md(c)?;
    // Shared fix (fork O): a server not resuming makes the early secret again with no PSK
    // (`ssl_gensecret`): a PSK accepted in a first ClientHello may be refused in the second,
    // after a HelloRetryRequest (anti-replay takes the session out of the cache). A client does
    // that itself when the ServerHello chose no PSK.
    let keep = c.neg.reused || !c.cfg.server;
    let mut sched = match c.hs.sh.keys.schedule.take() {
        Some(s) if s.hash() == hash && keep => s,
        _ => Schedule13::new(p, hash, None)?,
    };
    sched.into_handshake(p, shared)?;
    c.hs.sh.keys.schedule = Some(sched);
    Ok(())
}

/// `tls13_generate_master_secret`.
///
/// # Errors
/// The schedule isn't at the handshake stage, or the provider failed.
pub fn generate_master_secret(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    generate_master_secret_inner(c, p).in_func("tls13_generate_master_secret")
}

/// See [`generate_master_secret`].
fn generate_master_secret_inner(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    // A client that deferred its handshake write keys (early data, middlebox compatibility)
    // installs them after this, so their secret is kept now (shared fix, fork F; OpenSSL keeps
    // the handshake secret itself).
    let k = &c.hs.sh.keys;
    if !c.cfg.server && k.client_hs_secret.is_empty() && !k.handshake_traffic_hash.is_empty() {
        let sched = k.schedule.as_ref().ok_or_else(Error::internal)?;
        let s = sched.client_handshake_traffic(p, &k.handshake_traffic_hash)?;
        c.hs.sh.keys.client_hs_secret = s;
    }
    let sched = c.hs.sh.keys.schedule.as_mut().ok_or_else(Error::internal)?;
    sched.into_master(p)
}

/// `tls13_store_handshake_traffic_hash`: keeps the hash after the ServerHello.
///
/// # Errors
/// No transcript hash yet.
pub fn store_handshake_traffic_hash(c: &mut Connection) -> Result<()> {
    c.hs.sh.keys.handshake_traffic_hash = c.hs.transcript.current()?;
    Ok(())
}

/// `tls13_store_server_finished_hash`: keeps the hash up to the server's Finished.
///
/// # Errors
/// No transcript hash yet.
pub fn store_server_finished_hash(c: &mut Connection) -> Result<()> {
    c.hs.sh.keys.server_finished_hash = c.hs.transcript.current()?;
    Ok(())
}

/// A `which` flag test.
fn has(which: c_int, f: c_int) -> bool {
    which & f != 0
}

/// `tls13_change_cipher_state`: derives and installs the keys of one direction for one phase
/// (`which` is OpenSSL's `SSL3_CC_*` | `SSL3_CHANGE_CIPHER_*` combination): early data
/// (client write / server read, with the session's suite `early_cipher` and the hash of the
/// ClientHello alone), handshake, or application. Logs the secrets, keeps the Finished base
/// keys, and makes the resumption and exporter master secrets with the application keys.
///
/// # Errors
/// Missing state, the provider failed, or handshake data waits under the old read keys.
pub fn change_cipher_state13(
    c: &mut Connection,
    p: &dyn Provider,
    which: c_int,
    early_cipher: Option<&'static Cipher>,
) -> Result<()> {
    change_cipher_state13_inner(c, p, which, early_cipher).in_func("tls13_change_cipher_state")
}

/// See [`change_cipher_state13`].
fn change_cipher_state13_inner(
    c: &mut Connection,
    p: &dyn Provider,
    which: c_int,
    early_cipher: Option<&'static Cipher>,
) -> Result<()> {
    let client_side = (has(which, abi::SSL3_CC_CLIENT) && has(which, abi::SSL3_CC_WRITE))
        || (has(which, abi::SSL3_CC_SERVER) && has(which, abi::SSL3_CC_READ));
    let read = has(which, abi::SSL3_CC_READ);
    if has(which, abi::SSL3_CC_EARLY) {
        if !client_side {
            return Err(Error::internal());
        }
        let cp =
            early_cipher.ok_or(Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_BAD_PSK))?;
        let hash = hashes(crate::conn::common::version::of(abi::TLS1_3_VERSION), cp).0;
        let ch = c.hs.transcript.buffered().map(<[u8]>::to_vec);
        let hash_ch = match ch {
            Some(b) if !b.is_empty() => keysched::hash_of(p, hash, &b)?,
            _ => {
                return Err(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_BAD_HANDSHAKE_LENGTH,
                ));
            }
        };
        // A client sending early data under an external PSK uses that PSK's early secret
        // (`psksession->early_secret`), not the resumption one.
        let keys = &c.hs.sh.keys;
        let sched = if !c.cfg.server && c.neg.session.max_early_data == 0 {
            keys.psk_early.as_ref()
        } else {
            keys.schedule.as_ref()
        }
        .ok_or_else(Error::internal)?;
        let eem = sched.early_exporter_master(p, &hash_ch)?;
        let secret = sched.client_early_traffic(p, &hash_ch)?;
        c.neg.early_exporter_master = eem.bytes().to_vec();
        log_secret(c, keylog::EARLY_EXPORTER_SECRET, eem.bytes());
        log_secret(c, keylog::CLIENT_EARLY_TRAFFIC_SECRET, secret.bytes());
        if !read {
            // A client's early alerts go out in the clear (`set_plain_alerts`).
            c.rw.plain_alerts = !c.cfg.server;
        }
        let prot = protection13(p, cp, hash, secret.bytes())?;
        install13(c, read, prot)?;
        if read {
            // The early read keys count the early data they read (`ossl_get_max_early_data`).
            c.early_read = Some(crate::conn::EarlyRead {
                early: true,
                max: c.max_early_data(),
                count: 0,
            });
        }
        return Ok(());
    }
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let hash = handshake_md(c)?;
    let current = c.hs.transcript.current()?;
    let handshake = has(which, abi::SSL3_CC_HANDSHAKE);
    let sched = c.hs.sh.keys.schedule.as_ref().ok_or_else(Error::internal)?;
    let (secret, label) = if handshake {
        if client_side {
            // Shared fixes (tls-server, tls-client): a server that accepted early data reads
            // with these keys only after the EndOfEarlyData, and a client may install deferred
            // write keys (early data, middlebox mode) after the master secret: both use the secret
            // kept when the schedule moved on.
            let kept = c.hs.sh.keys.client_hs_secret.clone();
            let h = c.hs.sh.keys.handshake_traffic_hash.clone();
            let secret = if c.cfg.server && !kept.is_empty() {
                kept
            } else {
                match sched.client_handshake_traffic(p, &h) {
                    Ok(s) => s,
                    Err(_) if !kept.is_empty() => kept,
                    Err(e) => return Err(e),
                }
            };
            (secret, keylog::CLIENT_HANDSHAKE_TRAFFIC_SECRET)
        } else {
            (
                sched.server_handshake_traffic(p, &current)?,
                keylog::SERVER_HANDSHAKE_TRAFFIC_SECRET,
            )
        }
    } else {
        let sfh = c.hs.sh.keys.server_finished_hash.clone();
        if client_side {
            // The resumption master secret covers the whole handshake.
            let rms = sched.resumption_master(p, &current)?;
            c.hs.sh.keys.resumption_master = rms;
            (
                sched.client_application_traffic(p, &sfh)?,
                keylog::CLIENT_APPLICATION_TRAFFIC_SECRET,
            )
        } else {
            let s = sched.server_application_traffic(p, &sfh)?;
            let em = sched.exporter_master(p, &sfh)?;
            c.neg.exporter_master = em.bytes().to_vec();
            log_secret(c, keylog::EXPORTER_SECRET, em.bytes());
            (s, keylog::SERVER_APPLICATION_TRAFFIC_SECRET)
        }
    };
    log_secret(c, label, secret.bytes());
    match (handshake, client_side) {
        (true, true) => c.hs.sh.keys.client_hs_secret = secret.clone(),
        (true, false) => c.hs.sh.keys.server_hs_secret = secret.clone(),
        (false, true) => c.hs.sh.keys.client_app_secret = secret.clone(),
        (false, false) => c.hs.sh.keys.server_app_secret = secret.clone(),
    }
    if !read {
        c.rw.plain_alerts = false;
    }
    let prot = protection13(p, cp, hash, secret.bytes())?;
    install13(c, read, prot)?;
    if read && handshake && c.cfg.server {
        // A server's handshake read keys skip early data it rejected, within the limit.
        c.early_read = Some(crate::conn::EarlyRead {
            early: false,
            max: c.max_early_data(),
            count: 0,
        });
    }
    Ok(())
}

/// Shared addition (tls-server): derives the client's handshake traffic secret now (from the
/// hash stored after the ServerHello) and keeps it, for a server that accepted early data:
/// it installs the keys at the EndOfEarlyData ([`change_cipher_state13`] then uses this one).
///
/// # Errors
/// The schedule isn't at the handshake stage, or the provider failed.
pub fn keep_client_handshake_secret(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let sched = c.hs.sh.keys.schedule.as_ref().ok_or_else(Error::internal)?;
    let h = c.hs.sh.keys.handshake_traffic_hash.clone();
    c.hs.sh.keys.client_hs_secret = sched.client_handshake_traffic(p, &h)?;
    Ok(())
}

/// `tls13_update_key`: the next application traffic secret in one direction (KeyUpdate).
///
/// # Errors
/// Missing state, or the provider failed.
pub fn update_key(c: &mut Connection, p: &dyn Provider, sending: bool) -> Result<()> {
    update_key_inner(c, p, sending).in_func("tls13_update_key")
}

/// See [`update_key`].
fn update_key_inner(c: &mut Connection, p: &dyn Provider, sending: bool) -> Result<()> {
    let cp =
        c.hs.new_cipher
            .or(c.neg.cipher)
            .ok_or_else(Error::internal)?;
    let hash = hashes(c.neg.version, cp).0;
    let server_secret = c.cfg.server == sending;
    let old = if server_secret {
        &c.hs.sh.keys.server_app_secret
    } else {
        &c.hs.sh.keys.client_app_secret
    };
    let next = keysched::next_traffic_secret(p, hash, old.bytes())?;
    let prot = protection13(p, cp, hash, next.bytes())?;
    if server_secret {
        c.hs.sh.keys.server_app_secret = next.clone();
    } else {
        c.hs.sh.keys.client_app_secret = next.clone();
    }
    if sending {
        c.rw.set_protection(Mode::Tls13, prot);
    } else {
        check_boundary(c)?;
        c.rr.set_protection(Mode::Tls13, prot);
    }
    let label = if server_secret {
        "SERVER_TRAFFIC_SECRET_N"
    } else {
        "CLIENT_TRAFFIC_SECRET_N"
    };
    log_secret(c, label, next.bytes());
    Ok(())
}

/// `tls1_generate_master_secret`: TLS 1.0–1.2's master secret from the premaster secret, with
/// the Extended Master Secret's session hash when negotiated. Stored in
/// [`crate::conn::Negotiated::master_secret`] (and logged as `CLIENT_RANDOM` when the Finished
/// is made, as OpenSSL does).
///
/// # Errors
/// No suite or transcript hash, or the provider failed.
pub fn generate_master_secret12(c: &mut Connection, p: &dyn Provider, pms: &[u8]) -> Result<()> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let (_, prf) = hashes(c.neg.version, cp);
    let ms = if c.neg.ems {
        let h = c.hs.transcript.current()?;
        keysched::extended_master_secret(p, prf, pms, &h)?
    } else {
        keysched::master_secret(p, prf, pms, &c.hs.client_random, &c.hs.server_random)?
    };
    c.neg.master_secret = ms.bytes().to_vec();
    Ok(())
}

/// The key block's lengths for a TLS 1.0–1.2 suite: MAC key, cipher key, and IV (the AEADs'
/// fixed IV, or the CBC block length).
fn key_block_lengths(cp: &Cipher) -> Result<(usize, usize, usize, suites::Protection)> {
    let prot = cp.protection();
    Ok(match prot {
        suites::Protection::Aead(alg) => (0, alg.key_len(), cp.tls12_aead_iv_lengths().0, prot),
        suites::Protection::Cbc { cipher, mac } => {
            (mac.len(), cipher.key_len(), cipher.block_len(), prot)
        }
        suites::Protection::Null { mac } => (mac.len(), 0, 0, prot),
        suites::Protection::Unsupported => return Err(Error::internal()),
    })
}

/// `tls1_setup_key_block`: the key block from the master secret, once per handshake.
///
/// # Errors
/// An unsupported suite, or the provider failed.
pub fn setup_key_block(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    setup_key_block_inner(c, p).in_func("tls1_setup_key_block")
}

/// See [`setup_key_block`].
fn setup_key_block_inner(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.hs.sh.keys.key_block.is_some() {
        return Ok(());
    }
    // No suite yet (`ssl_cipher_get_evp` fails): the alert goes out with no ERR entry
    // (`SSLfatal_alert`).
    let cp =
        c.hs.new_cipher
            .ok_or(Error::alert_only(abi::SSL_AD_INTERNAL_ERROR))?;
    let (_, prf) = hashes(c.neg.version, cp);
    let (mac_len, key_len, iv_len, _) = key_block_lengths(cp)?;
    let kb = KeyBlock::new(
        p,
        prf,
        &c.neg.master_secret,
        &c.hs.server_random,
        &c.hs.client_random,
        mac_len,
        key_len,
        iv_len,
    )?;
    c.hs.sh.keys.key_block = Some(kb);
    Ok(())
}

/// `tls1_change_cipher_state`: installs TLS 1.0–1.2 protection in one direction
/// (`SSL3_CHANGE_CIPHER_*`), with encrypt-then-MAC when negotiated. The AEADs' explicit nonces
/// start at a random value, as OpenSSL's ciphers' invocation fields do.
///
/// # Errors
/// No key block, or the provider failed.
pub fn change_cipher_state12(c: &mut Connection, p: &dyn Provider, which: c_int) -> Result<()> {
    change_cipher_state12_inner(c, p, which).in_func("tls1_change_cipher_state")
}

/// See [`change_cipher_state12`].
fn change_cipher_state12_inner(c: &mut Connection, p: &dyn Provider, which: c_int) -> Result<()> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let kb =
        c.hs.sh
            .keys
            .key_block
            .as_ref()
            .ok_or_else(Error::internal)?;
    let client = which == abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE
        || which == abi::SSL3_CHANGE_CIPHER_SERVER_READ;
    let (mac, key, iv) = if client {
        (&kb.client_mac, &kb.client_key, &kb.client_iv)
    } else {
        (&kb.server_mac, &kb.server_key, &kb.server_iv)
    };
    let read = has(which, abi::SSL3_CC_READ);
    let version = c.neg.version;
    let (_, _, _, prot) = key_block_lengths(cp)?;
    let protection = match prot {
        suites::Protection::Aead(alg) => {
            let mut first = [0u8; 8];
            if !read {
                p.random(&mut first, false)?;
            }
            Protection::aead12(p, alg, key.bytes(), iv.bytes(), u64::from_be_bytes(first))?
        }
        suites::Protection::Cbc { cipher, mac: h } => Protection::cbc12(
            p,
            cipher,
            key.bytes(),
            iv.bytes(),
            h,
            mac.bytes(),
            version,
            c.neg.etm,
            !read,
        )?,
        suites::Protection::Null { mac: h } => Protection::cbc12(
            p,
            crate::crypto::CipherAlg::Null,
            &[],
            &[],
            h,
            mac.bytes(),
            version,
            c.neg.etm,
            !read,
        )?,
        suites::Protection::Unsupported => return Err(Error::internal()),
    };
    if read {
        check_boundary(c)?;
        c.rr.set_protection(Mode::Tls12(version), protection);
    } else {
        c.rw.set_protection(Mode::Tls12(version), protection);
    }
    Ok(())
}

/// `SSL_export_keying_material`: RFC 8446's exporter in TLS 1.3, RFC 5705's PRF in earlier
/// versions (`use_context` distinguishes an empty context from none there).
///
/// # Errors
/// No exporter secret yet (`SSL_R_...`: the caller checks `ossl_statem_export_allowed`), or the
/// provider failed.
pub fn export(
    c: &Connection,
    p: &dyn Provider,
    label: &[u8],
    context: &[u8],
    use_context: bool,
    len: usize,
) -> Result<Secret> {
    let cp = c
        .neg
        .cipher
        .or(c.hs.new_cipher)
        .ok_or_else(Error::internal)?;
    let (hash, prf) = hashes(c.neg.version, cp);
    if c.is_tls13() {
        // TLS 1.3 treats no context as an empty one.
        return keysched::export_13(p, hash, &c.neg.exporter_master, label, context, len);
    }
    keysched::export_12(
        p,
        prf,
        &c.neg.master_secret,
        label,
        &c.hs.client_random,
        &c.hs.server_random,
        use_context.then_some(context),
        len,
    )
}

/// `SSL_export_keying_material_early`.
///
/// # Errors
/// No early exporter secret, or the provider failed.
pub fn export_early(
    c: &Connection,
    p: &dyn Provider,
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Secret> {
    let cp = c
        .neg
        .cipher
        .or(c.hs.new_cipher)
        .ok_or_else(Error::internal)?;
    let hash = hashes(crate::conn::common::version::of(abi::TLS1_3_VERSION), cp).0;
    keysched::export_13(p, hash, &c.neg.early_exporter_master, label, context, len)
}
