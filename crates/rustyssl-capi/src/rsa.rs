//! RSA keys (`RSA`; `crypto/rsa/`): the object the default provider's RSA and RSA-PSS key
//! managers keep as their key data, as OpenSSL's are, so the legacy `RSA_*` functions (step
//! 4.3d) and `EVP_PKEY_get0_RSA` see the same key. The arithmetic and paddings are
//! `rustyssl_crypto::rsa`'s; this module gives them OpenSSL's digests (fetched with a library
//! context and properties), random octets, and error queue.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_R_NO_INVERSE, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_RSA, ERR_LIB_BN, ERR_R_INIT_FAIL,
    RSA_ASN1_VERSION_MULTI, RSA_FLAG_NO_BLINDING, RSA_FLAG_NON_FIPS_ALLOW, RSA_FLAG_TYPE_MASK,
    RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS, RSA_METHOD,
};
use rustyssl_abi::{
    ERR_LIB_RSA, ERR_R_BN_LIB, ERR_R_FETCH_FAILED, ERR_R_INTERNAL_ERROR, EVP_MD, EVP_MD_CTX,
    OSSL_LIB_CTX, RSA, RSA_R_BAD_E_VALUE, RSA_R_BAD_FIXED_HEADER_DECRYPT, RSA_R_BAD_PAD_BYTE_COUNT,
    RSA_R_BAD_SIGNATURE, RSA_R_BLOCK_TYPE_IS_NOT_01, RSA_R_DATA_GREATER_THAN_MOD_LEN,
    RSA_R_DATA_TOO_LARGE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE, RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
    RSA_R_DATA_TOO_SMALL, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY,
    RSA_R_FIRST_OCTET_INVALID, RSA_R_INVALID_DIGEST_LENGTH, RSA_R_INVALID_HEADER,
    RSA_R_INVALID_LENGTH, RSA_R_INVALID_MESSAGE_LENGTH, RSA_R_INVALID_PADDING,
    RSA_R_INVALID_TRAILER, RSA_R_KEY_SIZE_TOO_SMALL, RSA_R_LAST_OCTET_INVALID,
    RSA_R_MISSING_PRIVATE_KEY, RSA_R_MODULUS_TOO_LARGE, RSA_R_NO_PUBLIC_EXPONENT,
    RSA_R_NULL_BEFORE_BLOCK_MISSING, RSA_R_OAEP_DECODING_ERROR, RSA_R_PADDING_CHECK_FAILED,
    RSA_R_PKCS_DECODING_ERROR, RSA_R_SLEN_CHECK_FAILED, RSA_R_SLEN_RECOVERY_FAILED,
    RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD, RSA_R_UNKNOWN_ALGORITHM_TYPE,
    RSA_R_UNKNOWN_PADDING_TYPE, RSA_R_WRONG_SIGNATURE_LENGTH,
};
use rustyssl_crypto::bn::BigNum;
use rustyssl_crypto::rsa::{Entry, ExtraPrime, Hash, Key, Reason};

use crate::bn::{BN_clear_free, store, value};
use crate::ex_data::{CRYPTO_free_ex_data, CRYPTO_new_ex_data};

use crate::err;
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_up_ref,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::handle::{Handle, handle_type};
use crate::provider::{KeyLibctx, Ptr};
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};

/// The kind of key (`RSA_FLAG_TYPE_*`): RSA, or RSA-PSS, whose key type allows only PSS
/// signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Rsa,
    RsaPss,
}

/// A PSS key's restrictions (`RSA_PSS_PARAMS_30`): unrestricted when all zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pss30 {
    pub(crate) hash: c_int,
    pub(crate) mask_gen: c_int,
    pub(crate) mask_gen_hash: c_int,
    pub(crate) salt_len: c_int,
    pub(crate) trailer: c_int,
}

impl Pss30 {
    /// Whether the key is restricted.
    pub(crate) fn restricted(&self) -> bool {
        *self != Self::default()
    }
}

/// An RSA key's state: the numbers, its kind, and its PSS restrictions.
#[derive(Clone)]
pub(crate) struct RsaState {
    pub(crate) key: Key,
    pub(crate) kind: Kind,
    pub(crate) pss: Pss30,
}

/// The `BIGNUM`s the application has seen (`RSA_get0_*`) or given (`RSA_set0_*`): from then
/// on they hold the key's numbers, as an OpenSSL `RSA`'s own `BIGNUM`s do, so a `get0`
/// pointer stays valid and reads the key, and a number written through it is the key's.
/// Replaced ones are kept until the key is freed, so no `get0` pointer dangles.
#[derive(Default)]
pub(crate) struct Numbers {
    pub(crate) n: Ptr<BIGNUM>,
    pub(crate) e: Ptr<BIGNUM>,
    pub(crate) d: Ptr<BIGNUM>,
    pub(crate) p: Ptr<BIGNUM>,
    pub(crate) q: Ptr<BIGNUM>,
    pub(crate) dmp1: Ptr<BIGNUM>,
    pub(crate) dmq1: Ptr<BIGNUM>,
    pub(crate) iqmp: Ptr<BIGNUM>,
    /// Each extra prime's `r`, `d`, and `t`.
    pub(crate) extra: Vec<[Ptr<BIGNUM>; 3]>,
    retired: Vec<Ptr<BIGNUM>>,
}

/// One of an RSA key's numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    N,
    E,
    D,
    P,
    Q,
    Dmp1,
    Dmq1,
    Iqmp,
    /// An extra prime's `r` (0), `d` (1), or `t` (2).
    Extra(usize, usize),
}

impl Field {
    /// Whether OpenSSL keeps the number with `BN_FLG_CONSTTIME`: every private one.
    pub(crate) fn secret(self) -> bool {
        !matches!(self, Field::N | Field::E)
    }
}

/// The key's own number `f`.
pub(crate) fn key_field(key: &mut Key, f: Field) -> Option<&mut Option<BigNum>> {
    Some(match f {
        Field::N => &mut key.n,
        Field::E => &mut key.e,
        Field::D => &mut key.d,
        Field::P => &mut key.p,
        Field::Q => &mut key.q,
        Field::Dmp1 => &mut key.dmp1,
        Field::Dmq1 => &mut key.dmq1,
        Field::Iqmp => &mut key.iqmp,
        Field::Extra(..) => return None,
    })
}

impl Numbers {
    /// The handle slot of `f`, if it has one.
    pub(crate) fn slot(&mut self, f: Field) -> Option<&mut Ptr<BIGNUM>> {
        Some(match f {
            Field::N => &mut self.n,
            Field::E => &mut self.e,
            Field::D => &mut self.d,
            Field::P => &mut self.p,
            Field::Q => &mut self.q,
            Field::Dmp1 => &mut self.dmp1,
            Field::Dmq1 => &mut self.dmq1,
            Field::Iqmp => &mut self.iqmp,
            Field::Extra(i, j) => self.extra.get_mut(i)?.get_mut(j)?,
        })
    }

    /// Keeps `old` (if any) until the key is freed.
    pub(crate) fn retire(&mut self, old: Ptr<BIGNUM>) {
        if !old.0.is_null() {
            self.retired.push(old);
        }
    }

    /// Every handle, for freeing.
    fn all(&mut self) -> Vec<Ptr<BIGNUM>> {
        let mut v: Vec<Ptr<BIGNUM>> = core::mem::take(&mut self.retired);
        v.extend([
            self.n, self.e, self.d, self.p, self.q, self.dmp1, self.dmq1, self.iqmp,
        ]);
        for x in self.extra.drain(..) {
            v.extend(x);
        }
        v.retain(|p| !p.0.is_null());
        v
    }
}

/// The parts of an `RSA` the legacy functions see: its method, flags (`RSA_FLAG_*`, the type
/// bits aside, which the state's kind holds), and the numbers' handles.
pub(crate) struct Legacy {
    pub(crate) meth: Ptr<RSA_METHOD>,
    pub(crate) flags: c_int,
    pub(crate) numbers: Numbers,
    /// The ASN.1 version an `RSAPrivateKey` was decoded with, which OpenSSL keeps and encodes
    /// again; a multi-prime key's is `RSA_ASN1_VERSION_MULTI` whatever this holds.
    pub(crate) version: c_int,
    /// Whether a decoded `RSAPrivateKey` listed the other primes (an empty list is encoded
    /// again, as OpenSSL keeps its empty stack).
    pub(crate) listed_primes: bool,
    /// An RSA-PSS key's restrictions as OpenSSL's `rsa->pss` holds them (owned), or NULL:
    /// what `RSA_get0_pss_params` returns, prints, and limits legacy signing.
    pub(crate) pss: Ptr<rustyssl_abi::RSA_PSS_PARAMS>,
    /// The engine the method came from, with a functional reference, or NULL.
    pub(crate) engine: Ptr<rustyssl_abi::ENGINE>,
}

/// The key's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// An RSA key (`RSA`), shared by reference.
pub(crate) struct Rsa {
    pub(crate) libctx: KeyLibctx,
    /// `*_up_ref` and `RSA_free`'s count: the method's `finish` and the ex_data's free run
    /// when it reaches zero, with the handle still live.
    references: AtomicI32,
    /// `dirty_cnt`: bumped when the numbers change, so an `EVP_PKEY` holding the key as its
    /// legacy data knows its provider copy is stale.
    dirty: AtomicUsize,
    state: Mutex<RsaState>,
    legacy: Mutex<Legacy>,
    ex_data: ExData,
}

handle_type!(RSA => Rsa);

impl Drop for Rsa {
    fn drop(&mut self) {
        let lg = self
            .legacy
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let pss = core::mem::replace(&mut lg.pss, Ptr(ptr::null_mut()));
        // SAFETY: the key's own parameters, or NULL, freed once.
        unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss.0) };
        let numbers = lg.numbers.all();
        for b in numbers {
            // SAFETY: the key's own numbers, freed once.
            unsafe { BN_clear_free(b.0) };
        }
    }
}

/// `RSA_FLAG_TYPE_*`'s bits for a kind.
fn kind_flags(kind: Kind) -> c_int {
    match kind {
        Kind::Rsa => RSA_FLAG_TYPE_RSA,
        Kind::RsaPss => RSA_FLAG_TYPE_RSASSAPSS,
    }
}

impl Rsa {
    /// `rsa_new_intern`: an empty key of `kind` in `libctx` with the default method (whose
    /// `init` it runs), or NULL with the error raised.
    pub(crate) fn new_handle_in(libctx: *mut OSSL_LIB_CTX, kind: Kind) -> *mut RSA {
        // SAFETY: no engine.
        unsafe { Self::new_handle_engine(libctx, kind, ptr::null_mut()) }
    }

    /// `rsa_new_intern` with an engine: the key takes its method from `engine` (initialized),
    /// else from the default RSA engine if there is one, else the default method.
    ///
    /// # Safety
    /// `engine` is NULL or a live engine.
    pub(crate) unsafe fn new_handle_engine(
        libctx: *mut OSSL_LIB_CTX,
        kind: Kind,
        engine: *mut rustyssl_abi::ENGINE,
    ) -> *mut RSA {
        // SAFETY: the caller's guarantee.
        let chosen = unsafe {
            crate::engine::key_method(
                engine,
                crate::engine::table::ENGINE_get_default_RSA,
                crate::engine::ENGINE_get_RSA,
            )
        };
        let Ok((engine, emeth)) = chosen else {
            err::raise(
                ERR_LIB_RSA,
                rustyssl_abi::ERR_R_ENGINE_LIB,
                "rsa_new_intern",
            );
            return ptr::null_mut();
        };
        let meth = if emeth.is_null() {
            crate::rsa_meth::default_method()
        } else {
            emeth
        };
        // SAFETY: the default method is live (built in, or the application's).
        let mflags = unsafe { crate::rsa_meth::flags(meth) };
        let h = RSA::new_handle(Rsa {
            libctx: KeyLibctx::new(libctx),
            references: AtomicI32::new(1),
            dirty: AtomicUsize::new(0),
            state: Mutex::new(RsaState {
                key: Key::new(),
                kind,
                pss: Pss30::default(),
            }),
            legacy: Mutex::new(Legacy {
                meth: Ptr(meth.cast_mut()),
                flags: mflags & !RSA_FLAG_NON_FIPS_ALLOW,
                numbers: Numbers::default(),
                version: 0,
                listed_primes: false,
                pss: Ptr(ptr::null_mut()),
                engine: Ptr(engine),
            }),
            ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            })),
        });
        // SAFETY: just made.
        let Some(r) = (unsafe { rsa(h) }) else {
            return ptr::null_mut();
        };
        r.sync_flags();
        // SAFETY: the key's own ex_data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, h.cast(), r.ex_data()) } == 0 {
            // SAFETY: the only reference.
            unsafe { free(h) };
            return ptr::null_mut();
        }
        // SAFETY: the method is live; no lock is held while it runs.
        if let Some(init) = unsafe { crate::rsa_meth::init_fn(meth) }
            // SAFETY: the method's function takes the key.
            && unsafe { init(h) } == 0
        {
            err::raise(ERR_LIB_RSA, ERR_R_INIT_FAIL, "rsa_new_intern");
            // SAFETY: as above.
            unsafe { free(h) };
            return ptr::null_mut();
        }
        h
    }

    /// The key's application data.
    pub(crate) fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }

    /// The key's state, locked.
    pub(crate) fn lock(&self) -> MutexGuard<'_, RsaState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The legacy parts, locked (after the state, when both are).
    pub(crate) fn legacy(&self) -> MutexGuard<'_, Legacy> {
        self.legacy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the key's state, so an operation runs without holding the lock; the
    /// numbers the application holds as `BIGNUM`s are read from them.
    pub(crate) fn snapshot(&self) -> RsaState {
        let mut st = self.lock().clone();
        let mut lg = self.legacy();
        read_numbers(&mut lg.numbers, &mut st.key);
        st
    }

    /// The flags (`RSA_flags`), the type bits from the kind.
    pub(crate) fn flags(&self) -> c_int {
        let kind = self.lock().kind;
        (self.legacy().flags & !RSA_FLAG_TYPE_MASK) | kind_flags(kind)
    }

    /// Sets the flags, the kind and whether to blind following them.
    pub(crate) fn set_flags_to(&self, flags: c_int) {
        let mut st = self.lock();
        st.kind = if flags & RSA_FLAG_TYPE_MASK == RSA_FLAG_TYPE_RSASSAPSS {
            Kind::RsaPss
        } else {
            Kind::Rsa
        };
        st.key.blinding = flags & RSA_FLAG_NO_BLINDING == 0;
        self.legacy().flags = flags & !RSA_FLAG_TYPE_MASK;
    }

    /// Makes the state follow the flags.
    fn sync_flags(&self) {
        let f = self.flags();
        self.set_flags_to(f);
    }

    /// The method.
    pub(crate) fn meth(&self) -> *const RSA_METHOD {
        self.legacy().meth.0
    }
}

/// Reads the numbers the application holds into `key`.
pub(crate) fn read_numbers(numbers: &mut Numbers, key: &mut Key) {
    let read = |h: Ptr<BIGNUM>| {
        // SAFETY: the key's own number, live until the key is freed.
        (!h.0.is_null()).then(|| unsafe { value(h.0) }).flatten()
    };
    for f in [
        Field::N,
        Field::E,
        Field::D,
        Field::P,
        Field::Q,
        Field::Dmp1,
        Field::Dmq1,
        Field::Iqmp,
    ] {
        if let (Some(slot), Some(dst)) = (numbers.slot(f), key_field(key, f))
            && !slot.0.is_null()
        {
            *dst = read(*slot);
        }
    }
    for (x, h) in key.extra.iter_mut().zip(&numbers.extra) {
        for (dst, h) in [&mut x.r, &mut x.d, &mut x.t].into_iter().zip(h) {
            if let Some(v) = read(*h) {
                *dst = v;
            }
        }
    }
}

/// Stores `key`'s numbers in the handles the application holds, so they keep holding the
/// key's (after a generation into the key); a handle whose number the key no longer has is
/// retired.
pub(crate) fn write_numbers(numbers: &mut Numbers, key: &Key) {
    let fields = [
        (Field::N, &key.n),
        (Field::E, &key.e),
        (Field::D, &key.d),
        (Field::P, &key.p),
        (Field::Q, &key.q),
        (Field::Dmp1, &key.dmp1),
        (Field::Dmq1, &key.dmq1),
        (Field::Iqmp, &key.iqmp),
    ];
    for (f, v) in fields {
        let Some(slot) = numbers.slot(f) else {
            continue;
        };
        if slot.0.is_null() {
            continue;
        }
        match v {
            // SAFETY: the key's own number.
            Some(v) => unsafe {
                store(slot.0, v.clone());
            },
            None => {
                let old = core::mem::take(slot);
                numbers.retire(old);
            }
        }
    }
    let extra = core::mem::take(&mut numbers.extra);
    for (i, h) in extra.into_iter().enumerate() {
        match key.extra.get(i) {
            Some(x) => {
                for (h, v) in h.iter().zip([&x.r, &x.d, &x.t]) {
                    if !h.0.is_null() {
                        // SAFETY: the key's own number.
                        unsafe { store(h.0, v.clone()) };
                    }
                }
                numbers.extra.push(h);
            }
            None => {
                for h in h {
                    numbers.retire(h);
                }
            }
        }
    }
}

impl Rsa {
    /// Changes the key's numbers with `f`, keeping the handles the application holds in step.
    pub(crate) fn update_key(&self, f: impl FnOnce(&mut Key)) {
        let mut st = self.lock();
        let mut lg = self.legacy();
        read_numbers(&mut lg.numbers, &mut st.key);
        f(&mut st.key);
        write_numbers(&mut lg.numbers, &st.key);
        self.touch();
    }

    /// Takes the numbers a decode filled (`d2i_RSAPrivateKey`): each `BIGNUM` becomes the
    /// key's number for its field (one that already is, decoded in place, has its new value
    /// read); `extra` replaces the other primes when given, with whether the encoding listed
    /// them; `version` is kept as decoded.
    ///
    /// # Safety
    /// Each number is NULL or a live `BIGNUM` the key takes, or already holds.
    pub(crate) unsafe fn adopt(
        &self,
        fields: &[(Field, *mut BIGNUM)],
        extra: Option<(Vec<[*mut BIGNUM; 3]>, bool)>,
        version: Option<c_int>,
    ) {
        let mut st = self.lock();
        let mut lg = self.legacy();
        read_numbers(&mut lg.numbers, &mut st.key);
        for &(f, b) in fields {
            if b.is_null() {
                continue;
            }
            // SAFETY: the caller's guarantee.
            let v = unsafe { value(b) };
            if let Some(dst) = key_field(&mut st.key, f) {
                *dst = v;
            }
            if let Some(slot) = lg.numbers.slot(f) {
                let old = core::mem::replace(slot, Ptr(b));
                if old.0 != b {
                    lg.numbers.retire(old);
                }
            }
        }
        if let Some((list, listed)) = extra {
            let mut primes = Vec::with_capacity(list.len());
            let mut handles = Vec::with_capacity(list.len());
            for [r, d, t] in list {
                // SAFETY: as above.
                let (Some(rv), Some(dv), Some(tv)) =
                    (unsafe { value(r) }, unsafe { value(d) }, unsafe {
                        value(t)
                    })
                else {
                    continue;
                };
                primes.push(ExtraPrime {
                    r: rv,
                    d: dv,
                    t: tv,
                });
                handles.push([Ptr(r), Ptr(d), Ptr(t)]);
            }
            st.key.extra = primes;
            let old = core::mem::replace(&mut lg.numbers.extra, handles);
            for h in old {
                for b in h {
                    lg.numbers.retire(b);
                }
            }
            lg.listed_primes = listed;
        }
        if let Some(v) = version {
            lg.version = v;
            st.key.multi = v == RSA_ASN1_VERSION_MULTI;
        }
        drop(lg);
        drop(st);
        self.touch();
    }

    /// Gives the key the restrictions `pss` (which it takes), freeing any it had.
    pub(crate) fn set_pss_params(&self, pss: *mut rustyssl_abi::RSA_PSS_PARAMS) {
        let old = core::mem::replace(&mut self.legacy().pss, Ptr(pss));
        // SAFETY: the key's own parameters, or NULL, no longer its.
        unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(old.0) };
    }

    /// Marks the numbers changed (`dirty_cnt++`).
    pub(crate) fn touch(&self) {
        self.dirty.fetch_add(1, Ordering::AcqRel);
    }

    /// The dirty count.
    pub(crate) fn dirty_cnt(&self) -> usize {
        self.dirty.load(Ordering::Acquire)
    }
}

/// The key behind an `RSA` pointer (key data).
///
/// # Safety
/// `rsa` is NULL or a live handle.
pub(crate) unsafe fn rsa<'a>(rsa: *const RSA) -> Option<&'a Rsa> {
    // SAFETY: the caller's guarantee.
    unsafe { RSA::get(rsa) }
}

/// `RSA_free`: drops a reference; at the last, runs the method's `finish` and frees the
/// ex_data, then the key. NULL does nothing.
///
/// # Safety
/// `r` is NULL or a live key whose reference the caller gives up.
pub(crate) unsafe fn free(r: *mut RSA) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { RSA::hold(r) }) else {
        return;
    };
    let left = held
        .references
        .fetch_sub(1, Ordering::AcqRel)
        .saturating_sub(1);
    if left != 0 {
        return;
    }
    let meth = held.meth();
    // SAFETY: the key's method, live; no lock is held while it runs.
    if let Some(finish) = unsafe { crate::rsa_meth::finish_fn(meth) } {
        // SAFETY: the method's function takes the key.
        unsafe { finish(r) };
    }
    let engine = core::mem::replace(&mut held.legacy().engine, Ptr(ptr::null_mut()));
    // SAFETY: the key's functional reference to its engine, or NULL.
    unsafe { crate::engine::ENGINE_finish(engine.0) };
    // SAFETY: the key's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r.cast(), held.ex_data()) };
    // SAFETY: the last reference; the hold keeps the key until this returns.
    unsafe { RSA::free(r) };
}

/// `RSA_up_ref`: adds a reference; false for NULL or another type.
///
/// # Safety
/// `r` is NULL or a live key.
pub(crate) unsafe fn up_ref(r: *const RSA) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { rsa(r) }) else {
        return false;
    };
    // The key's count alone: `free` drops the handle's one `Arc` reference at the last.
    k.references.fetch_add(1, Ordering::AcqRel);
    true
}

/// The `RSA_R_*` (or `ERR_R_*`) code of a reason.
pub(crate) fn reason_code(reason: Reason) -> c_int {
    match reason {
        Reason::ModulusTooLarge => RSA_R_MODULUS_TOO_LARGE,
        Reason::BadEValue => RSA_R_BAD_E_VALUE,
        Reason::UnknownPaddingType => RSA_R_UNKNOWN_PADDING_TYPE,
        Reason::DataTooLargeForModulus => RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
        Reason::DataTooLargeForKeySize => RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE,
        Reason::DataTooSmallForKeySize => RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE,
        Reason::DataGreaterThanModLen => RSA_R_DATA_GREATER_THAN_MOD_LEN,
        Reason::DataTooSmall => RSA_R_DATA_TOO_SMALL,
        Reason::DataTooLarge => RSA_R_DATA_TOO_LARGE,
        Reason::MissingPrivateKey => RSA_R_MISSING_PRIVATE_KEY,
        Reason::NoPublicExponent => RSA_R_NO_PUBLIC_EXPONENT,
        Reason::PaddingCheckFailed => RSA_R_PADDING_CHECK_FAILED,
        Reason::PkcsDecodingError => RSA_R_PKCS_DECODING_ERROR,
        Reason::OaepDecodingError => RSA_R_OAEP_DECODING_ERROR,
        Reason::InvalidPadding => RSA_R_INVALID_PADDING,
        Reason::BlockTypeIsNot01 => RSA_R_BLOCK_TYPE_IS_NOT_01,
        Reason::BadFixedHeaderDecrypt => RSA_R_BAD_FIXED_HEADER_DECRYPT,
        Reason::NullBeforeBlockMissing => RSA_R_NULL_BEFORE_BLOCK_MISSING,
        Reason::BadPadByteCount => RSA_R_BAD_PAD_BYTE_COUNT,
        Reason::InvalidLength => RSA_R_INVALID_LENGTH,
        Reason::KeySizeTooSmall => RSA_R_KEY_SIZE_TOO_SMALL,
        Reason::SlenCheckFailed(_) => RSA_R_SLEN_CHECK_FAILED,
        Reason::FirstOctetInvalid => RSA_R_FIRST_OCTET_INVALID,
        Reason::LastOctetInvalid => RSA_R_LAST_OCTET_INVALID,
        Reason::SlenRecoveryFailed => RSA_R_SLEN_RECOVERY_FAILED,
        Reason::BadSignature => RSA_R_BAD_SIGNATURE,
        Reason::InvalidHeader => RSA_R_INVALID_HEADER,
        Reason::InvalidTrailer => RSA_R_INVALID_TRAILER,
        Reason::WrongSignatureLength => RSA_R_WRONG_SIGNATURE_LENGTH,
        Reason::InvalidMessageLength => RSA_R_INVALID_MESSAGE_LENGTH,
        Reason::InvalidDigestLength => RSA_R_INVALID_DIGEST_LENGTH,
        Reason::UnknownAlgorithmType => RSA_R_UNKNOWN_ALGORITHM_TYPE,
        Reason::AsnObjectNotKnownForMd => RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD,
        Reason::DigestTooBigForRsaKey => RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY,
        Reason::Internal => ERR_R_INTERNAL_ERROR,
        Reason::FetchFailed => ERR_R_FETCH_FAILED,
        Reason::BnLib => ERR_R_BN_LIB,
        Reason::NoInverse => BN_R_NO_INVERSE,
    }
}

/// Raises the entries an RSA operation left, in order, each from the OpenSSL function that
/// raises it; each is cleared afterwards when its entry says so, without a branch on that.
pub(crate) fn raise_all(raised: &[Entry]) {
    for e in raised {
        match e.reason {
            Reason::SlenCheckFailed(Some((expected, retrieved))) => err::raise_with_text(
                ERR_LIB_RSA,
                RSA_R_SLEN_CHECK_FAILED,
                e.func,
                &format!("expected: {expected} retrieved: {retrieved}"),
            ),
            Reason::NoInverse => err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, e.func),
            r => err::raise(ERR_LIB_RSA, reason_code(r), e.func),
        }
        err::clear_last_constant_time(e.clear);
    }
}

/// A digest for the RSA paddings: a fetched `EVP_MD`, with a reference this holds.
pub(crate) struct Md(*mut EVP_MD);

impl Md {
    /// `EVP_MD_fetch(libctx, name, properties)`, or `None` (the fetch's errors raised).
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `properties` is NULL or a string.
    pub(crate) unsafe fn fetch(
        libctx: *mut OSSL_LIB_CTX,
        name: &CStr,
        properties: *const c_char,
    ) -> Option<Self> {
        // SAFETY: the caller's guarantee; a string.
        let md = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), properties) };
        (!md.is_null()).then_some(Self(md))
    }

    /// Another reference to `md`, or `None` for NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest.
    pub(crate) unsafe fn of(md: *const EVP_MD) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        (!md.is_null() && unsafe { EVP_MD_up_ref(md.cast_mut()) } == 1).then(|| Self(md.cast_mut()))
    }

    /// The digest.
    pub(crate) fn ptr(&self) -> *mut EVP_MD {
        self.0
    }
}

impl Clone for Md {
    fn clone(&self) -> Self {
        // SAFETY: this holds a reference to a live digest.
        unsafe { EVP_MD_up_ref(self.0) };
        Self(self.0)
    }
}

impl Drop for Md {
    fn drop(&mut self) {
        // SAFETY: the reference this holds.
        unsafe { EVP_MD_free(self.0) };
    }
}

// SAFETY: a fetched digest is shared between threads in OpenSSL; this only holds a reference.
unsafe impl Send for Md {}
// SAFETY: as above.
unsafe impl Sync for Md {}

impl Hash for Md {
    fn size(&self) -> usize {
        // SAFETY: a live digest.
        usize::try_from(unsafe { EVP_MD_get_size(self.0) }).unwrap_or(0)
    }

    fn block_size(&self) -> usize {
        // SAFETY: a live digest.
        usize::try_from(unsafe { EVP_MD_get_block_size(self.0) }).unwrap_or(0)
    }

    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        struct Ctx(*mut EVP_MD_CTX);
        impl Drop for Ctx {
            fn drop(&mut self) {
                // SAFETY: the context made below, or NULL.
                unsafe { EVP_MD_CTX_free(self.0) };
            }
        }
        // SAFETY: no preconditions.
        let ctx = Ctx(unsafe { EVP_MD_CTX_new() });
        // SAFETY: the context; the digest.
        if ctx.0.is_null() || unsafe { EVP_DigestInit_ex(ctx.0, self.0, ptr::null_mut()) } != 1 {
            return None;
        }
        for p in parts {
            // SAFETY: the context; the part's octets.
            if unsafe { EVP_DigestUpdate(ctx.0, p.as_ptr().cast(), p.len()) } != 1 {
                return None;
            }
        }
        let mut out = vec![0u8; 64.max(self.size())];
        let mut n: c_uint = 0;
        // SAFETY: the context; room for the digest.
        if unsafe { EVP_DigestFinal_ex(ctx.0, out.as_mut_ptr(), &raw mut n) } != 1 {
            return None;
        }
        out.truncate(usize::try_from(n).ok()?);
        Some(out)
    }
}

/// Random octets from `libctx`'s public generator (`RAND_bytes_ex`, strength 0).
pub(crate) fn public_random(libctx: *mut OSSL_LIB_CTX) -> impl FnMut(&mut [u8]) -> bool {
    move |buf: &mut [u8]| {
        // SAFETY: the library context; the buffer.
        (unsafe { RAND_bytes_ex(libctx, buf.as_mut_ptr(), buf.len(), 0) }) == 1
    }
}

/// Random octets from `libctx`'s private generator (`RAND_priv_bytes_ex`, strength 0).
pub(crate) fn private_random(libctx: *mut OSSL_LIB_CTX) -> impl FnMut(&mut [u8]) -> bool {
    move |buf: &mut [u8]| {
        // SAFETY: the library context; the buffer.
        (unsafe { RAND_priv_bytes_ex(libctx, buf.as_mut_ptr(), buf.len(), 0) }) == 1
    }
}
