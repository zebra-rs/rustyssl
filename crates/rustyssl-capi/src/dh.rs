//! DH keys (`DH`; `crypto/dh/dh_lib.c`, `dh_group_params.c`, `dh_rfc5114.c`): domain
//! parameters (`crate::ffc::Params`, with the named group they are cached), the private key
//! length, and the key pair, with their method, flags, application data, and references.
//!
//! As with `RSA`, the numbers the application sees (`DH_get0_*`) or gives (`DH_set0_*`) are
//! kept as the key's own `BIGNUM`s from then on, so a `get0` pointer lives as long as the key
//! and reads (and writes) its number.

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_FLG_CONSTTIME, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_DH, DH, DH_METHOD,
    DH_R_INVALID_PARAMETER_NID, ENGINE, ERR_LIB_DH, ERR_R_INIT_FAIL, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::BigNum;
use rustyssl_crypto::ffc as groups;

use crate::bn::{BN_clear_free, BN_security_bits, BN_set_flags, new_bignum, store, value};
use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffc;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

/// A DH key's state: its parameters, private key length, and key pair.
#[derive(Clone, Default)]
pub(crate) struct DhState {
    pub(crate) params: ffc::Params,
    /// The generated private key's maximum length in bits (`int32_t length`), 0 for none.
    pub(crate) length: i32,
    pub(crate) pub_key: Option<BigNum>,
    pub(crate) priv_key: Option<BigNum>,
}

/// One of a DH key's numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    P,
    Q,
    G,
    Pub,
    Priv,
}

impl Field {
    const ALL: [Self; 5] = [Self::P, Self::Q, Self::G, Self::Pub, Self::Priv];

    /// The state's number `f`.
    pub(crate) fn of(self, st: &mut DhState) -> &mut Option<BigNum> {
        match self {
            Self::P => &mut st.params.p,
            Self::Q => &mut st.params.q,
            Self::G => &mut st.params.g,
            Self::Pub => &mut st.pub_key,
            Self::Priv => &mut st.priv_key,
        }
    }
}

/// The `BIGNUM`s the application has seen or given: the key's numbers from then on.
/// Replaced ones are kept until the key is freed, so no `get0` pointer dangles.
#[derive(Default)]
pub(crate) struct Numbers {
    slots: [Ptr<BIGNUM>; 5],
    retired: Vec<Ptr<BIGNUM>>,
}

impl Numbers {
    fn index(f: Field) -> usize {
        match f {
            Field::P => 0,
            Field::Q => 1,
            Field::G => 2,
            Field::Pub => 3,
            Field::Priv => 4,
        }
    }

    pub(crate) fn slot(&mut self, f: Field) -> &mut Ptr<BIGNUM> {
        let i = Self::index(f);
        // Five slots, one per field.
        #[expect(clippy::indexing_slicing, reason = "an index below the array's length")]
        &mut self.slots[i]
    }

    fn retire(&mut self, old: Ptr<BIGNUM>) {
        if !old.0.is_null() {
            self.retired.push(old);
        }
    }

    /// Reads the numbers the application holds into `st`.
    pub(crate) fn read(&mut self, st: &mut DhState) {
        for f in Field::ALL {
            let h = *self.slot(f);
            if !h.0.is_null() {
                // SAFETY: the key's own number, live until the key is freed.
                *f.of(st) = unsafe { value(h.0) };
            }
        }
    }

    /// Stores `st`'s numbers in the handles the application holds; a handle whose number the
    /// key no longer has is retired.
    pub(crate) fn write(&mut self, st: &mut DhState) {
        for f in Field::ALL {
            let slot = self.slot(f);
            if slot.0.is_null() {
                continue;
            }
            match f.of(st) {
                // SAFETY: the key's own number.
                Some(v) => unsafe {
                    store(slot.0, v.clone());
                },
                None => {
                    let old = core::mem::take(slot);
                    self.retire(old);
                }
            }
        }
    }
}

/// The parts of a `DH` the legacy functions see: its method, flags, and numbers' handles.
pub(crate) struct Legacy {
    pub(crate) meth: Ptr<DH_METHOD>,
    pub(crate) flags: c_int,
    pub(crate) numbers: Numbers,
}

/// The key's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// A DH key (`DH`), shared by reference.
pub(crate) struct Dh {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    references: AtomicI32,
    /// `dirty_cnt`.
    dirty: AtomicUsize,
    state: Mutex<DhState>,
    legacy: Mutex<Legacy>,
    ex_data: ExData,
}

handle_type!(DH => Dh);

impl Drop for Dh {
    fn drop(&mut self) {
        let lg = self
            .legacy
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let mut all = core::mem::take(&mut lg.numbers.retired);
        all.extend(lg.numbers.slots);
        for b in all.into_iter().filter(|b| !b.0.is_null()) {
            // SAFETY: the key's own numbers, freed once.
            unsafe { BN_clear_free(b.0) };
        }
    }
}

impl Dh {
    /// `dh_new_intern`: an empty key in `libctx` with the default method (whose `init` it
    /// runs), or NULL with the error raised.
    pub(crate) fn new_handle_in(libctx: *mut OSSL_LIB_CTX) -> *mut DH {
        let meth = crate::dh_meth::default_or_builtin();
        // SAFETY: a live method.
        let mflags = unsafe { crate::dh_meth::flags(meth) };
        let h = DH::new_handle(Dh {
            libctx: Ptr(libctx),
            references: AtomicI32::new(1),
            dirty: AtomicUsize::new(0),
            state: Mutex::new(DhState::default()),
            legacy: Mutex::new(Legacy {
                meth: Ptr(meth.cast_mut()),
                flags: mflags,
                numbers: Numbers::default(),
            }),
            ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            })),
        });
        // SAFETY: just made.
        let Some(d) = (unsafe { dh(h) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the key's own ex_data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, h.cast(), d.ex_data()) } == 0 {
            // SAFETY: the only reference.
            unsafe { free(h) };
            return ptr::null_mut();
        }
        // SAFETY: the method is live; no lock is held while it runs.
        if let Some(init) = unsafe { crate::dh_meth::fns_of(meth) }.and_then(|f| f.init)
            // SAFETY: the method's function takes the key.
            && unsafe { init(h) } == 0
        {
            err::raise(ERR_LIB_DH, ERR_R_INIT_FAIL, "dh_new_intern");
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

    /// The state, locked.
    pub(crate) fn lock(&self) -> MutexGuard<'_, DhState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The legacy parts, locked (after the state, when both are).
    pub(crate) fn legacy(&self) -> MutexGuard<'_, Legacy> {
        self.legacy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the state, with the numbers the application holds read in.
    pub(crate) fn snapshot(&self) -> DhState {
        let mut st = self.lock().clone();
        self.legacy().numbers.read(&mut st);
        st
    }

    /// Replaces the state (its numbers stored in the application's handles too).
    pub(crate) fn replace(&self, mut new: DhState) {
        let mut st = self.lock();
        self.legacy().numbers.write(&mut new);
        *st = new;
        drop(st);
        self.touch();
    }

    /// Bumps the dirty count.
    pub(crate) fn touch(&self) {
        self.dirty.fetch_add(1, Ordering::AcqRel);
    }

    /// The method.
    pub(crate) fn meth(&self) -> *const DH_METHOD {
        self.legacy().meth.0
    }

    /// The flags.
    pub(crate) fn flags(&self) -> c_int {
        self.legacy().flags
    }

    /// Sets the flags.
    pub(crate) fn set_flags_to(&self, flags: c_int) {
        self.legacy().flags = flags;
    }

    /// The key's number `f` as its own `BIGNUM`, made the first time (NULL if it has none).
    fn get0(&self, f: Field) -> *const BIGNUM {
        let mut st = self.lock();
        let mut lg = self.legacy();
        lg.numbers.read(&mut st);
        let Some(v) = f.of(&mut st).clone() else {
            return ptr::null();
        };
        let slot = lg.numbers.slot(f);
        if slot.0.is_null() {
            let b = new_bignum(v, false);
            if f == Field::Priv {
                // SAFETY: just made.
                unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
            }
            *slot = Ptr(b);
        }
        slot.0
    }

    /// `DH_set0_*`'s step: the key takes `b` as its number `f` (keeping the old one alive).
    ///
    /// # Safety
    /// `b` is a live `BIGNUM` the caller gives up.
    unsafe fn set0(&self, st: &mut DhState, lg: &mut Legacy, f: Field, b: *mut BIGNUM) {
        // SAFETY: the caller's guarantee.
        *f.of(st) = unsafe { value(b) };
        let slot = lg.numbers.slot(f);
        let old = core::mem::replace(slot, Ptr(b));
        if old.0 != b {
            lg.numbers.retire(old);
        }
    }

    /// `ossl_dh_cache_named_group`: the named group `p`, `g` (and `q`, if set) are, cached
    /// with its key length, its `q` filled in if missing.
    pub(crate) fn cache_named_group(st: &mut DhState) {
        st.params.nid = 0;
        let (Some(p), Some(g)) = (&st.params.p, &st.params.g) else {
            return;
        };
        if let Some(group) = ffc::named_group(p, st.params.q.as_ref(), g) {
            if st.params.q.is_none() {
                st.params.q = Some(group.q.clone());
            }
            st.params.nid = group.uid;
            st.params.keylength = group.keylength;
        }
    }
}

/// The key behind a `DH` pointer.
///
/// # Safety
/// `d` is NULL or a live handle.
pub(crate) unsafe fn dh<'a>(d: *const DH) -> Option<&'a Dh> {
    // SAFETY: the caller's guarantee.
    unsafe { DH::get(d) }
}

/// `DH_free`: drops a reference; at the last, runs the method's `finish` and frees the
/// ex_data, then the key.
///
/// # Safety
/// `d` is NULL or a live key whose reference the caller gives up.
pub(crate) unsafe fn free(d: *mut DH) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { DH::hold(d) }) else {
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
    if let Some(finish) = unsafe { crate::dh_meth::fns_of(meth) }.and_then(|f| f.finish) {
        // SAFETY: the method's function takes the key.
        unsafe { finish(d) };
    }
    // SAFETY: the key's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, d.cast(), held.ex_data()) };
    // SAFETY: the last reference; the hold keeps the key until this returns.
    unsafe { DH::free(d) };
}

/// Adds a reference.
///
/// # Safety
/// `d` is NULL or a live key.
pub(crate) unsafe fn up_ref(d: *const DH) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dh(d) }) else {
        return false;
    };
    k.references.fetch_add(1, Ordering::AcqRel);
    true
}

/// A new key with `params` (and no key pair) in `libctx`.
pub(crate) fn with_params(libctx: *mut OSSL_LIB_CTX, params: ffc::Params, length: i32) -> *mut DH {
    let h = Dh::new_handle_in(libctx);
    // SAFETY: just made, or NULL.
    if let Some(d) = unsafe { dh(h) } {
        let mut st = d.lock();
        st.params = params;
        st.length = length;
        drop(st);
        d.touch();
    }
    h
}

/// Puts `v` where `out` points, if it does.
///
/// # Safety
/// `out` is NULL or writable.
unsafe fn put(out: *mut *const BIGNUM, v: *const BIGNUM) {
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(v) };
    }
}

ffi_export! {
    /// A new empty key with the default method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_new() -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        Dh::new_handle_in(ptr::null_mut())
    }
}

ffi_export! {
    /// `DH_new` with an engine: NULL only (rustyssl has no engines; another pointer aborts).
    ///
    /// # Safety
    /// `engine` is NULL.
    pub unsafe extern "C" fn DH_new_method(engine: *mut ENGINE) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        if !engine.is_null() {
            crate::stub::unimplemented("DH_new_method with an engine (rustyssl has none)");
        }
        Dh::new_handle_in(ptr::null_mut())
    }
}

ffi_export! {
    /// Drops a reference; at the last, the method's `finish` runs and the key is freed. NULL
    /// does nothing.
    ///
    /// # Safety
    /// `r` is NULL or a live key whose reference the caller gives up.
    pub unsafe extern "C" fn DH_free(r: *mut DH)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(r) };
    }
}

ffi_export! {
    /// Adds a reference. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn DH_up_ref(r: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { up_ref(r) })
    }
}

ffi_export! {
    /// Replaces the key's method: the old one's `finish` runs, then the new one's `init`. 1.
    ///
    /// # Safety
    /// `dh` is a live key; `meth` is a live method that outlives its use.
    pub unsafe extern "C" fn DH_set_method(dh: *mut DH, meth: *const DH_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        let old = k.meth();
        // SAFETY: the key's method, live; no lock is held while it runs.
        if let Some(finish) = unsafe { crate::dh_meth::fns_of(old) }.and_then(|f| f.finish) {
            // SAFETY: the method's function takes the key.
            unsafe { finish(dh) };
        }
        k.legacy().meth = Ptr(meth.cast_mut());
        // SAFETY: the caller's method.
        if let Some(init) = unsafe { crate::dh_meth::fns_of(meth) }.and_then(|f| f.init) {
            // SAFETY: as above.
            unsafe { init(dh) };
        }
        1
    }
}

ffi_export! {
    /// The key's engine: always NULL (rustyssl has no engines).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_get0_engine(_d: *mut DH) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// Sets the key's application data at `idx`.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DH_set_ex_data(d: *mut DH, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dh(d) }) else { return 0 };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_set_ex_data(k.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The key's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DH_get_ex_data(d: *const DH, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dh(d) }) else { return ptr::null_mut() };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_get_ex_data(k.ex_data(), idx) }
    }
}

ffi_export! {
    /// The prime's bits, or -1 without one.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_bits(dh: *const DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return -1 };
        k.snapshot().params.p.map_or(-1, |p| c_int::try_from(p.num_bits()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// The prime's octets, or -1 without one.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_size(dh: *const DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return -1 };
        k.snapshot().params.p.map_or(-1, |p| c_int::try_from(p.num_bytes()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// The security strength of the prime with the subgroup's (or private key length's) bits,
    /// or -1 without a prime.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_security_bits(dh: *const DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return -1 };
        let st = k.snapshot();
        let n = match (&st.params.q, st.length) {
            (Some(q), _) => c_int::try_from(q.num_bits()).unwrap_or(c_int::MAX),
            (None, l) if l != 0 => l,
            _ => -1,
        };
        let Some(p) = st.params.p else { return -1 };
        // SAFETY: no preconditions.
        unsafe { BN_security_bits(c_int::try_from(p.num_bits()).unwrap_or(c_int::MAX), n) }
    }
}

ffi_export! {
    /// The parameters (each where asked; NULL for a missing one).
    ///
    /// # Safety
    /// `dh` is a live key; each output is NULL or writable.
    pub unsafe extern "C" fn DH_get0_pqg(dh: *const DH, p: *mut *const BIGNUM, q: *mut *const BIGNUM, g: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return };
        for (out, f) in [(p, Field::P), (q, Field::Q), (g, Field::G)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, k.get0(f)) };
            }
        }
    }
}

ffi_export! {
    /// Sets the parameters: the key takes each number that isn't NULL (p and g must end up
    /// set), then caches the named group they are. 0 when it would lack p or g.
    ///
    /// # Safety
    /// `dh` is a live key; each number is NULL or a live `BIGNUM` the caller gives up.
    pub unsafe extern "C" fn DH_set0_pqg(dh: *mut DH, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        let mut st = k.lock();
        let mut lg = k.legacy();
        lg.numbers.read(&mut st);
        if (st.params.p.is_none() && p.is_null()) || (st.params.g.is_none() && g.is_null()) {
            return 0;
        }
        for (f, b) in [(Field::P, p), (Field::Q, q), (Field::G, g)] {
            if !b.is_null() {
                // SAFETY: the caller's number.
                unsafe { k.set0(&mut st, &mut lg, f, b) };
            }
        }
        Dh::cache_named_group(&mut st);
        lg.numbers.write(&mut st);
        drop(lg);
        drop(st);
        k.touch();
        1
    }
}

ffi_export! {
    /// The private key length.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get_length(dh: *const DH) -> c_long
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(0, |k| c_long::from(k.lock().length))
    }
}

ffi_export! {
    /// Sets the private key length (kept as 32 bits, as OpenSSL keeps it). 1.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_set_length(dh: *mut DH, length: c_long) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        let low = u32::try_from(length.rem_euclid(1 << 32)).unwrap_or(0);
        k.lock().length = i32::from_ne_bytes(low.to_ne_bytes());
        k.touch();
        1
    }
}

ffi_export! {
    /// The key pair (each where asked; NULL for a missing one).
    ///
    /// # Safety
    /// `dh` is a live key; each output is NULL or writable.
    pub unsafe extern "C" fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return };
        for (out, f) in [(pub_key, Field::Pub), (priv_key, Field::Priv)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, k.get0(f)) };
            }
        }
    }
}

ffi_export! {
    /// Sets the key pair: the key takes each number that isn't NULL. 1.
    ///
    /// # Safety
    /// `dh` is a live key; each number is NULL or a live `BIGNUM` the caller gives up.
    pub unsafe extern "C" fn DH_set0_key(dh: *mut DH, pub_key: *mut BIGNUM, priv_key: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        let mut st = k.lock();
        let mut lg = k.legacy();
        lg.numbers.read(&mut st);
        for (f, b) in [(Field::Pub, pub_key), (Field::Priv, priv_key)] {
            if !b.is_null() {
                if f == Field::Priv {
                    // SAFETY: the caller's number.
                    unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
                }
                // SAFETY: as above.
                unsafe { k.set0(&mut st, &mut lg, f, b) };
            }
        }
        drop(lg);
        drop(st);
        k.touch();
        1
    }
}

ffi_export! {
    /// The prime p, or NULL.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get0_p(dh: *const DH) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(ptr::null(), |k| k.get0(Field::P))
    }
}

ffi_export! {
    /// The subgroup order q, or NULL.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get0_q(dh: *const DH) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(ptr::null(), |k| k.get0(Field::Q))
    }
}

ffi_export! {
    /// The generator g, or NULL.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get0_g(dh: *const DH) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(ptr::null(), |k| k.get0(Field::G))
    }
}

ffi_export! {
    /// The public key, or NULL.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get0_pub_key(dh: *const DH) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(ptr::null(), |k| k.get0(Field::Pub))
    }
}

ffi_export! {
    /// The private key, or NULL.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_get0_priv_key(dh: *const DH) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(ptr::null(), |k| k.get0(Field::Priv))
    }
}

ffi_export! {
    /// Clears `flags`.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_clear_flags(dh: *mut DH, flags: c_int)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::dh(dh) } {
            k.set_flags_to(k.flags() & !flags);
        }
    }
}

ffi_export! {
    /// The flags among `flags` that are set.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_test_flags(dh: *const DH, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(0, |k| k.flags() & flags)
    }
}

ffi_export! {
    /// Sets `flags`.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_set_flags(dh: *mut DH, flags: c_int)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::dh(dh) } {
            k.set_flags_to(k.flags() | flags);
        }
    }
}

ffi_export! {
    /// The NID of the named group the parameters are (RFC 5114's 1 to 3), or `NID_undef`.
    ///
    /// # Safety
    /// `dh` is NULL or a live key.
    pub unsafe extern "C" fn DH_get_nid(dh: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::dh(dh) }.map_or(0, |k| k.lock().params.nid)
    }
}

/// `ossl_dh_new_by_nid_ex`: a key with the named group `nid`'s parameters (its NID cached),
/// or NULL with `DH_R_INVALID_PARAMETER_NID`.
pub(crate) fn new_by_nid_ex(libctx: *mut OSSL_LIB_CTX, nid: c_int) -> *mut DH {
    let Some(group) = groups::by_uid(nid) else {
        err::raise(
            ERR_LIB_DH,
            DH_R_INVALID_PARAMETER_NID,
            "ossl_dh_new_by_nid_ex",
        );
        return ptr::null_mut();
    };
    let mut params = ffc::Params::default();
    params.set_named_group(group);
    params.nid = group.uid;
    with_params(libctx, params, 0)
}

ffi_export! {
    /// A key with the parameters of the named group `nid` (`NID_ffdhe*`, `NID_modp_*`, or RFC
    /// 5114's 1 to 3).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_new_by_nid(nid: c_int) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        new_by_nid_ex(ptr::null_mut(), nid)
    }
}

/// `make_dh(x)`: a key with an RFC 5114 group's numbers (its NID not cached, as in OpenSSL).
fn rfc5114(uid: c_int) -> *mut DH {
    let Some(group) = groups::by_uid(uid) else {
        return ptr::null_mut();
    };
    let params = ffc::Params {
        p: Some(group.p.clone()),
        q: Some(group.q.clone()),
        g: Some(group.g.clone()),
        ..ffc::Params::default()
    };
    with_params(ptr::null_mut(), params, 0)
}

ffi_export! {
    /// RFC 5114's 1024-bit group with a 160-bit subgroup.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_get_1024_160() -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        rfc5114(1)
    }
}

ffi_export! {
    /// RFC 5114's 2048-bit group with a 224-bit subgroup.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_get_2048_224() -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        rfc5114(2)
    }
}

ffi_export! {
    /// RFC 5114's 2048-bit group with a 256-bit subgroup.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_get_2048_256() -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        rfc5114(3)
    }
}

ffi_export! {
    /// A new key with `dh`'s parameters (`int_dh_param_copy`): no key pair, and the private
    /// key length only for parameters without q.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DHparams_dup(dh: *const DH) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return ptr::null_mut() };
        let st = k.snapshot();
        let length = if st.params.q.is_none() { st.length } else { 0 };
        with_params(ptr::null_mut(), st.params, length)
    }
}
