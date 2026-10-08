//! The hash table (`OPENSSL_LH_*`, `OPENSSL_LH_COMPFUNC(3)`). The typed `lh_TYPE_*` wrappers
//! from `DEFINE_LHASH_OF_EX` are inline functions over these, which install "thunks" that call
//! the typed callbacks.
//!
//! OpenSSL's table is a linear hash: buckets split one at a time as the load rises and merge as
//! it falls, and `OPENSSL_LH_doall` walks the buckets from the last to the first. Applications
//! see that order, so the table here is the same algorithm step for step: the same bucket for
//! each hash, the same splits and merges, and the same chain order.
//!
//! Callbacks may use the table: OpenSSL's own session cache deletes the item it is visiting
//! from inside `doall`. So no lock is held while a callback runs, nodes live in a slab and are
//! named by generation-checked references, and a walk that meets a node deleted under it stops
//! that chain instead of following freed memory as OpenSSL would.

use core::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};
use core::ptr;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use libc::FILE;
use rustssl_abi::{
    BIO, ERR_LIB_CRYPTO, LH_LOAD_MULT, OPENSSL_LH_COMPFUNC, OPENSSL_LH_COMPFUNCTHUNK,
    OPENSSL_LH_DOALL_FUNC, OPENSSL_LH_DOALL_FUNC_THUNK, OPENSSL_LH_DOALL_FUNCARG,
    OPENSSL_LH_DOALL_FUNCARG_THUNK, OPENSSL_LH_HASHFUNC, OPENSSL_LH_HASHFUNCTHUNK, OPENSSL_LHASH,
};

use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::stack::Element;

/// The fewest buckets OpenSSL allocates, and below which it stops merging.
const MIN_NODES: c_uint = 16;

type HashFn = unsafe extern "C" fn(*const c_void) -> c_ulong;
type CompareFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// A node, named by its slot and the slot's generation when it was made.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NodeRef {
    slot: usize,
    generation: u64,
}

struct Node {
    data: Element,
    hash: c_ulong,
    next: Option<NodeRef>,
}

struct Slot {
    generation: u64,
    node: Option<Node>,
}

struct Table {
    /// OpenSSL's `b`: `num_alloc_nodes` chain heads.
    buckets: Vec<Option<NodeRef>>,
    slots: Vec<Slot>,
    free_slots: Vec<usize>,
    hash: HashFn,
    comp: CompareFn,
    hashw: OPENSSL_LH_HASHFUNCTHUNK,
    compw: OPENSSL_LH_COMPFUNCTHUNK,
    daw: OPENSSL_LH_DOALL_FUNC_THUNK,
    daaw: OPENSSL_LH_DOALL_FUNCARG_THUNK,
    num_nodes: c_uint,
    num_alloc_nodes: c_uint,
    p: c_uint,
    pmax: c_uint,
    up_load: c_ulong,
    down_load: c_ulong,
    num_items: c_ulong,
    error: c_int,
}

/// What a hash table handle points to.
pub(crate) struct Lhash(RwLock<Table>);

handle_type!(OPENSSL_LHASH => Lhash);

/// `n` as an index; `c_uint` always fits.
fn index(n: c_uint) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// `LH_LOAD_MULT`, the scale of the load figures.
fn load_mult() -> c_ulong {
    c_ulong::from(LH_LOAD_MULT.unsigned_abs())
}

impl Table {
    fn node(&self, r: NodeRef) -> Option<&Node> {
        let slot = self.slots.get(r.slot)?;
        (slot.generation == r.generation).then_some(slot.node.as_ref())?
    }

    fn node_mut(&mut self, r: NodeRef) -> Option<&mut Node> {
        let slot = self.slots.get_mut(r.slot)?;
        (slot.generation == r.generation).then_some(slot.node.as_mut())?
    }

    fn set_next(&mut self, r: NodeRef, next: Option<NodeRef>) {
        if let Some(node) = self.node_mut(r) {
            node.next = next;
        }
    }

    fn allocate(&mut self, node: Node) -> NodeRef {
        match self.free_slots.pop() {
            Some(slot) => {
                let entry = self.slots.get_mut(slot);
                let generation = entry.map_or(0, |s| {
                    s.node = Some(node);
                    s.generation
                });
                NodeRef { slot, generation }
            }
            None => {
                self.slots.push(Slot {
                    generation: 0,
                    node: Some(node),
                });
                NodeRef {
                    slot: self.slots.len() - 1,
                    generation: 0,
                }
            }
        }
    }

    fn release(&mut self, r: NodeRef) {
        if let Some(slot) = self.slots.get_mut(r.slot)
            && slot.generation == r.generation
            && slot.node.is_some()
        {
            slot.node = None;
            slot.generation = slot.generation.wrapping_add(1);
            self.free_slots.push(r.slot);
        }
    }

    /// The bucket a hash belongs in (as OpenSSL's `getrn` computes it).
    fn bucket_of(&self, hash: c_ulong) -> usize {
        let pmax = c_ulong::from(self.pmax.max(1));
        let mut bucket = hash % pmax;
        if bucket < c_ulong::from(self.p) {
            bucket = hash % c_ulong::from(self.num_alloc_nodes.max(1));
        }
        usize::try_from(bucket).unwrap_or(0)
    }

    fn head(&self, bucket: usize) -> Option<NodeRef> {
        self.buckets.get(bucket).copied().flatten()
    }

    fn set_head(&mut self, bucket: usize, head: Option<NodeRef>) {
        if let Some(b) = self.buckets.get_mut(bucket) {
            *b = head;
        }
    }

    /// The nodes of a bucket's chain, in order.
    fn chain(&self, bucket: usize) -> Vec<NodeRef> {
        let mut nodes = Vec::new();
        let mut at = self.head(bucket);
        while let Some(r) = at {
            let Some(node) = self.node(r) else { break };
            nodes.push(r);
            at = node.next;
        }
        nodes
    }

    /// Links `nodes` into a chain starting at `bucket`.
    fn link(&mut self, bucket: usize, nodes: &[NodeRef]) {
        self.set_head(bucket, nodes.first().copied());
        for (i, r) in nodes.iter().enumerate() {
            self.set_next(*r, nodes.get(i + 1).copied());
        }
    }

    /// Adds a bucket by splitting bucket `p` (OpenSSL's `expand`). Nodes that move keep the
    /// order OpenSSL gives them, which reverses them.
    fn expand(&mut self) {
        let nni = self.num_alloc_nodes;
        let (p, pmax) = (self.p, self.pmax);
        if p + 1 >= pmax {
            let doubled = nni.saturating_mul(2);
            self.buckets.resize(index(doubled), None);
            self.pmax = nni;
            self.num_alloc_nodes = doubled;
            self.p = 0;
        } else {
            self.p += 1;
        }
        self.num_nodes += 1;
        let (from, to) = (index(p), index(p) + index(pmax));
        let mut stay = Vec::new();
        let mut moved = Vec::new();
        for r in self.chain(from) {
            let hash = self.node(r).map_or(0, |n| n.hash);
            if hash % c_ulong::from(nni.max(1)) == c_ulong::from(p) {
                stay.push(r);
            } else {
                moved.insert(0, r);
            }
        }
        self.link(from, &stay);
        self.link(to, &moved);
    }

    /// Removes the last bucket, appending its chain to the bucket it came from (OpenSSL's
    /// `contract`).
    fn contract(&mut self) {
        let last = index(self.p) + index(self.pmax) - 1;
        let moved = self.chain(last);
        self.set_head(last, None);
        if self.p == 0 {
            self.buckets.truncate(index(self.pmax));
            self.num_alloc_nodes /= 2;
            self.pmax /= 2;
            self.p = self.pmax.saturating_sub(1);
        } else {
            self.p -= 1;
        }
        self.num_nodes -= 1;
        let target = index(self.p);
        let mut chain = self.chain(target);
        chain.extend(moved);
        self.link(target, &chain);
    }

    /// `num_items * LH_LOAD_MULT / num_nodes`, with C's unsigned arithmetic.
    fn load(&self) -> c_ulong {
        self.num_items.wrapping_mul(load_mult()) / c_ulong::from(self.num_nodes.max(1))
    }

    /// Removes every item, keeping the buckets (OpenSSL's `OPENSSL_LH_flush`).
    fn flush(&mut self) {
        for i in 0..self.slots.len() {
            let generation = self.slots.get(i).map_or(0, |s| s.generation);
            self.release(NodeRef {
                slot: i,
                generation,
            });
        }
        self.buckets.iter_mut().for_each(|b| *b = None);
        self.num_items = 0;
    }
}

impl Lhash {
    fn read(&self) -> RwLockReadGuard<'_, Table> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Table> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hashes `data` and looks for an equal item (OpenSSL's `getrn`), calling the application's
    /// hash and comparison functions without holding the lock.
    ///
    /// # Safety
    /// The table's callbacks accept `data` and the stored items.
    unsafe fn lookup(&self, data: *const c_void) -> (c_ulong, Option<NodeRef>) {
        let (hash_fn, hashw, comp, compw) = {
            let table = self.read();
            (table.hash, table.hashw, table.comp, table.compw)
        };
        let hash = match hashw {
            // SAFETY: the caller's guarantee.
            Some(thunk) => unsafe { thunk(data, Some(hash_fn)) },
            // SAFETY: as above.
            None => unsafe { hash_fn(data) },
        };
        let candidates: Vec<(NodeRef, c_ulong, Element)> = {
            let table = self.read();
            table
                .chain(table.bucket_of(hash))
                .into_iter()
                .filter_map(|r| table.node(r).map(|n| (r, n.hash, n.data)))
                .collect()
        };
        for (r, node_hash, item) in candidates {
            if node_hash != hash {
                continue;
            }
            let compared = match compw {
                // SAFETY: as above.
                Some(thunk) => unsafe { thunk(item.0, data, Some(comp)) },
                // SAFETY: as above.
                None => unsafe { comp(item.0, data) },
            };
            if compared == 0 {
                return (hash, Some(r));
            }
        }
        (hash, None)
    }
}

/// The table behind `handle`, or `None` for null.
///
/// # Safety
/// `handle` is null or a live table handle that outlives `'a`.
unsafe fn table<'a>(handle: *const OPENSSL_LHASH) -> Option<&'a Lhash> {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_LHASH::get(handle) }
}

/// The default hash, `OPENSSL_LH_strhash`, for `void *` items.
unsafe extern "C" fn default_hash(data: *const c_void) -> c_ulong {
    // SAFETY: a table with the default hash holds strings.
    unsafe { strhash(data.cast()) }
}

/// The default comparison, `strcmp`, for `void *` items (only equality matters).
unsafe extern "C" fn default_compare(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: a table with the default comparison holds strings.
    let a = unsafe { CStr::from_ptr(a.cast()) };
    // SAFETY: as above.
    let b = unsafe { CStr::from_ptr(b.cast()) };
    match a.cmp(b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `OPENSSL_LH_strhash`. Each byte is a C `char`, so bytes from 0x80 hash differently where
/// `char` is signed (x86-64, macOS) and where it isn't (Linux on Arm), as OpenSSL's do.
///
/// # Safety
/// `text` is null or a NUL-terminated string.
unsafe fn strhash(text: *const c_char) -> c_ulong {
    if text.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
    let mut ret: c_ulong = 0;
    let mut n: c_ulong = 0x100;
    for byte in bytes {
        let c = c_char::from_ne_bytes([*byte]);
        let v = n | c_ulong::from_ne_bytes(i64::from(c).to_ne_bytes());
        n = n.wrapping_add(0x100);
        let r = u32::try_from(((v >> 2) ^ v) & 0x0f).unwrap_or(0);
        ret = (ret << r) | (ret >> (32 - r));
        ret &= 0xFFFF_FFFF;
        ret ^= v.wrapping_mul(v);
    }
    (ret >> 16) ^ ret
}

/// Calls a doall callback on `item`, through the thunk if there is one. Without a thunk the
/// function is called directly, where OpenSSL's would call a null thunk and crash
/// (docs/DEVIATIONS.md); a null function does nothing.
///
/// # Safety
/// The thunk and function accept the table's items.
unsafe fn visit(item: Element, thunk: OPENSSL_LH_DOALL_FUNC_THUNK, func: OPENSSL_LH_DOALL_FUNC) {
    let Some(func) = func else { return };
    match thunk {
        // SAFETY: the caller's guarantee.
        Some(thunk) => unsafe { thunk(item.0.cast_mut(), Some(func)) },
        // SAFETY: as above.
        None => unsafe { func(item.0.cast_mut()) },
    }
}

/// [`visit`] with an argument.
///
/// # Safety
/// As for [`visit`]; `arg` is what the function expects.
unsafe fn visit_arg(
    item: Element,
    thunk: OPENSSL_LH_DOALL_FUNCARG_THUNK,
    func: OPENSSL_LH_DOALL_FUNCARG,
    arg: *mut c_void,
) {
    let Some(func) = func else { return };
    match thunk {
        // SAFETY: the caller's guarantee.
        Some(thunk) => unsafe { thunk(item.0.cast_mut(), arg, Some(func)) },
        // SAFETY: as above.
        None => unsafe { func(item.0.cast_mut(), arg) },
    }
}

/// Visits every item, from the last bucket to the first and along each chain (OpenSSL's
/// `doall_util_fn`). The next node is read before the callback runs, so the callback may delete
/// the item it is given.
///
/// # Safety
/// `handle` is null or a live table handle; `callback` accepts its items.
unsafe fn doall(handle: *const OPENSSL_LHASH, mut callback: impl FnMut(Element)) {
    // SAFETY: the caller's guarantee.
    let Some(table) = (unsafe { self::table(handle) }) else {
        return;
    };
    let buckets = index(table.read().num_nodes);
    for i in (0..buckets).rev() {
        let mut at = table.read().head(i);
        while let Some(r) = at {
            let Some((item, next)) = table.read().node(r).map(|n| (n.data, n.next)) else {
                break;
            };
            callback(item);
            at = next;
        }
    }
}

ffi_export! {
    /// Returns a new table with the hash function `h` and comparison `c`; null ones mean
    /// strings (`OPENSSL_LH_strhash` and `strcmp`).
    ///
    /// # Safety
    /// `h` and `c` are null or accept the items the table will hold.
    pub unsafe extern "C" fn OPENSSL_LH_new(h: OPENSSL_LH_HASHFUNC, c: OPENSSL_LH_COMPFUNC) -> *mut OPENSSL_LHASH
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        OPENSSL_LHASH::new_handle(Lhash(RwLock::new(Table {
            buckets: vec![None; index(MIN_NODES)],
            slots: Vec::new(),
            free_slots: Vec::new(),
            hash: h.unwrap_or(default_hash),
            comp: c.unwrap_or(default_compare),
            hashw: None,
            compw: None,
            daw: None,
            daaw: None,
            num_nodes: MIN_NODES / 2,
            num_alloc_nodes: MIN_NODES,
            p: 0,
            pmax: MIN_NODES / 2,
            up_load: 2 * load_mult(),
            down_load: load_mult(),
            num_items: 0,
            error: 0,
        })))
    }
}

ffi_export! {
    /// Sets the thunks through which the typed `lh_TYPE_*` wrappers' callbacks are called.
    /// Returns `lh` (null for null).
    ///
    /// # Safety
    /// `lh` is null or a live table; the thunks are null or accept its items and callbacks.
    pub unsafe extern "C" fn OPENSSL_LH_set_thunks(lh: *mut OPENSSL_LHASH, hw: OPENSSL_LH_HASHFUNCTHUNK, cw: OPENSSL_LH_COMPFUNCTHUNK, daw: OPENSSL_LH_DOALL_FUNC_THUNK, daaw: OPENSSL_LH_DOALL_FUNCARG_THUNK) -> *mut OPENSSL_LHASH
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(table) = unsafe { table(lh) } {
            let mut table = table.write();
            table.hashw = hw;
            table.compw = cw;
            table.daw = daw;
            table.daaw = daaw;
        }
        lh
    }
}

ffi_export! {
    /// Frees the table, not its items. Null is ignored.
    ///
    /// # Safety
    /// `lh` is null or a live table, not used afterwards.
    pub unsafe extern "C" fn OPENSSL_LH_free(lh: *mut OPENSSL_LHASH)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_LHASH::free(lh) };
    }
}

ffi_export! {
    /// Removes every item (not freeing them); the table keeps its size.
    ///
    /// # Safety
    /// `lh` is null or a live table.
    pub unsafe extern "C" fn OPENSSL_LH_flush(lh: *mut OPENSSL_LHASH)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(table) = unsafe { table(lh) } {
            table.write().flush();
        }
    }
}

ffi_export! {
    /// Adds `data`, or replaces an equal item and returns it. Returns null for a new item (or
    /// a null table, where OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table whose callbacks accept `data`.
    pub unsafe extern "C" fn OPENSSL_LH_insert(lh: *mut OPENSSL_LHASH, data: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(table) = (unsafe { table(lh) }) else {
            return ptr::null_mut();
        };
        {
            let mut t = table.write();
            t.error = 0;
            if t.up_load <= t.load() {
                t.expand();
            }
        }
        // SAFETY: as above.
        let (hash, found) = unsafe { table.lookup(data) };
        let mut t = table.write();
        if let Some(node) = found.and_then(|r| t.node_mut(r)) {
            return core::mem::replace(&mut node.data, Element(data)).0.cast_mut();
        }
        let bucket = t.bucket_of(hash);
        let new = t.allocate(Node {
            data: Element(data),
            hash,
            next: None,
        });
        let mut chain = t.chain(bucket);
        chain.push(new);
        t.link(bucket, &chain);
        t.num_items = t.num_items.wrapping_add(1);
        ptr::null_mut()
    }
}

ffi_export! {
    /// Removes the item equal to `data` and returns it; null if there is none (or for a null
    /// table, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table whose callbacks accept `data`.
    pub unsafe extern "C" fn OPENSSL_LH_delete(lh: *mut OPENSSL_LHASH, data: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(table) = (unsafe { table(lh) }) else {
            return ptr::null_mut();
        };
        table.write().error = 0;
        // SAFETY: as above.
        let (_, found) = unsafe { table.lookup(data) };
        let mut t = table.write();
        let Some((r, hash, item)) = found.and_then(|r| t.node(r).map(|n| (r, n.hash, n.data)))
        else {
            return ptr::null_mut();
        };
        let bucket = t.bucket_of(hash);
        let mut chain = t.chain(bucket);
        chain.retain(|n| *n != r);
        t.link(bucket, &chain);
        t.release(r);
        t.num_items = t.num_items.wrapping_sub(1);
        if t.num_nodes > MIN_NODES && t.down_load >= t.load() {
            t.contract();
        }
        item.0.cast_mut()
    }
}

ffi_export! {
    /// Returns the item equal to `data`, or null (also for a null table, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table whose callbacks accept `data`.
    pub unsafe extern "C" fn OPENSSL_LH_retrieve(lh: *mut OPENSSL_LHASH, data: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(table) = (unsafe { table(lh) }) else {
            return ptr::null_mut();
        };
        // Only a nonzero error is cleared, so concurrent readers don't write.
        if table.read().error != 0 {
            table.write().error = 0;
        }
        // SAFETY: as above.
        let (_, found) = unsafe { table.lookup(data) };
        let t = table.read();
        found
            .and_then(|r| t.node(r))
            .map_or(ptr::null_mut(), |n| n.data.0.cast_mut())
    }
}

ffi_export! {
    /// Calls `func` on every item, through the table's thunk, from the last bucket to the
    /// first. The callback may delete the item it is given. Null tables and functions do
    /// nothing; a table without thunks calls `func` directly (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table; `func` accepts its items.
    pub unsafe extern "C" fn OPENSSL_LH_doall(lh: *mut OPENSSL_LHASH, func: OPENSSL_LH_DOALL_FUNC)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let thunk = unsafe { table(lh) }.and_then(|t| t.read().daw);
        let callback = |item| {
            // SAFETY: the caller's guarantee about `func` and the table's thunk.
            unsafe { visit(item, thunk, func) }
        };
        // SAFETY: as above.
        unsafe { doall(lh, callback) };
    }
}

ffi_export! {
    /// `OPENSSL_LH_doall` with an argument for `func`.
    ///
    /// # Safety
    /// As for `OPENSSL_LH_doall`; `arg` is what `func` expects.
    pub unsafe extern "C" fn OPENSSL_LH_doall_arg(lh: *mut OPENSSL_LHASH, func: OPENSSL_LH_DOALL_FUNCARG, arg: *mut c_void)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let thunk = unsafe { table(lh) }.and_then(|t| t.read().daaw);
        let callback = |item| {
            // SAFETY: the caller's guarantee about `func`, `arg`, and the table's thunk.
            unsafe { visit_arg(item, thunk, func, arg) }
        };
        // SAFETY: as above.
        unsafe { doall(lh, callback) };
    }
}

ffi_export! {
    /// `OPENSSL_LH_doall_arg` through the given thunk instead of the table's.
    ///
    /// # Safety
    /// As for `OPENSSL_LH_doall_arg`; `daaw` is null or accepts the items and `fn_`.
    pub unsafe extern "C" fn OPENSSL_LH_doall_arg_thunk(lh: *mut OPENSSL_LHASH, daaw: OPENSSL_LH_DOALL_FUNCARG_THUNK, fn_: OPENSSL_LH_DOALL_FUNCARG, arg: *mut c_void)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let callback = |item| {
            // SAFETY: the caller's guarantee about the thunk, `fn_`, and `arg`.
            unsafe { visit_arg(item, daaw, fn_, arg) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { doall(lh, callback) };
    }
}

ffi_export! {
    /// OpenSSL's string hash, as `OPENSSL_LH_new` uses by default; 0 for null or "".
    ///
    /// # Safety
    /// `c` is null or a NUL-terminated string.
    pub unsafe extern "C" fn OPENSSL_LH_strhash(c: *const c_char) -> c_ulong
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { strhash(c) }
    }
}

ffi_export! {
    /// Returns the number of items; 0 for null.
    ///
    /// # Safety
    /// `lh` is null or a live table.
    pub unsafe extern "C" fn OPENSSL_LH_num_items(lh: *const OPENSSL_LHASH) -> c_ulong
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { table(lh) }.map_or(0, |t| t.read().num_items)
    }
}

ffi_export! {
    /// Returns the load (times 256) at or below which deleting merges buckets; 0 for null
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table.
    pub unsafe extern "C" fn OPENSSL_LH_get_down_load(lh: *const OPENSSL_LHASH) -> c_ulong
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { table(lh) }.map_or(0, |t| t.read().down_load)
    }
}

ffi_export! {
    /// Sets the load (times 256) at or below which deleting merges buckets; 0 stops merging.
    ///
    /// # Safety
    /// `lh` is null or a live table.
    pub unsafe extern "C" fn OPENSSL_LH_set_down_load(lh: *mut OPENSSL_LHASH, dl: c_ulong)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(table) = unsafe { table(lh) } {
            table.write().down_load = dl;
        }
    }
}

ffi_export! {
    /// Returns the number of allocation failures in the last insert, delete, or retrieve.
    /// rustssl's tables don't fail to allocate, so it's 0 (also for null, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `lh` is null or a live table.
    pub unsafe extern "C" fn OPENSSL_LH_error(lh: *mut OPENSSL_LHASH) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { table(lh) }.map_or(0, |t| t.read().error)
    }
}

/// The text of the statistics functions, line by line.
enum Stats {
    Summary,
    Nodes,
    Usage,
}

fn stats(table: &Table, kind: Stats) -> Vec<String> {
    let lengths: Vec<usize> = (0..index(table.num_nodes))
        .map(|i| table.chain(i).len())
        .collect();
    match kind {
        Stats::Summary => {
            let mut lines = vec![
                format!("num_items             = {}\n", table.num_items),
                format!("num_nodes             = {}\n", table.num_nodes),
                format!("num_alloc_nodes       = {}\n", table.num_alloc_nodes),
            ];
            for name in [
                "num_expands          ",
                "num_expand_reallocs  ",
                "num_contracts        ",
                "num_contract_reallocs",
                "num_hash_calls       ",
                "num_comp_calls       ",
                "num_insert           ",
                "num_replace          ",
                "num_delete           ",
                "num_no_delete        ",
                "num_retrieve         ",
                "num_retrieve_miss    ",
                "num_hash_comps       ",
            ] {
                lines.push(format!("{name} = 0\n"));
            }
            lines
        }
        Stats::Nodes => lengths
            .iter()
            .enumerate()
            .map(|(i, n)| format!("node {i:6} -> {n:3}\n"))
            .collect(),
        Stats::Usage => {
            let used = lengths.iter().filter(|n| **n != 0).count();
            let total: usize = lengths.iter().sum();
            let mut lines = vec![
                format!("{used} nodes used out of {}\n", table.num_nodes),
                format!("{total} items\n"),
            ];
            // As C's integer division: the whole part and two decimals, truncated.
            let ratio = |of: usize| {
                Some((
                    total.checked_div(of)?,
                    (total.checked_rem(of)? * 100).checked_div(of)?,
                ))
            };
            if let (Some(load), Some(actual)) = (ratio(index(table.num_nodes)), ratio(used)) {
                lines.push(format!(
                    "load {}.{:02}  actual load {}.{:02}\n",
                    load.0, load.1, actual.0, actual.1
                ));
            }
            lines
        }
    }
}

/// Writes a statistics report to `fp`, a line per write as OpenSSL's file BIO does. Null
/// tables and files print nothing (OpenSSL's would crash, docs/DEVIATIONS.md).
///
/// # Safety
/// `lh` is null or a live table; `fp` is null or an open `FILE`.
unsafe fn print_stats(lh: *const OPENSSL_LHASH, fp: *mut FILE, kind: Stats) {
    // SAFETY: the caller's guarantee.
    let Some(table) = (unsafe { table(lh) }) else {
        return;
    };
    if fp.is_null() {
        return;
    }
    let lines = stats(&table.read(), kind);
    for line in lines {
        // SAFETY: the caller's guarantee about `fp`; `line` holds `len` bytes.
        if unsafe { libc::fwrite(line.as_ptr().cast(), line.len(), 1, fp) } != 1 {
            return;
        }
    }
}

/// Writes a statistics report to `out`, a line per `BIO_write` as OpenSSL's `BIO_printf`s.
/// A null table prints nothing (docs/DEVIATIONS.md).
///
/// # Safety
/// `lh` is null or a live table; `out` is null or a live BIO.
unsafe fn print_stats_bio(lh: *const OPENSSL_LHASH, out: *mut BIO, kind: Stats) {
    // SAFETY: the caller's guarantee.
    let Some(table) = (unsafe { table(lh) }) else {
        return;
    };
    let lines = stats(&table.read(), kind);
    for line in lines {
        let len = c_int::try_from(line.len()).unwrap_or(c_int::MAX);
        // SAFETY: the caller's guarantee about `out`; `line` holds `len` bytes.
        unsafe { crate::bio::BIO_write(out, line.as_ptr().cast(), len) };
    }
}

ffi_export! {
    /// Prints the item and bucket counts to `out` (deprecated).
    ///
    /// # Safety
    /// `lh` is null or a live table; `out` is null or a live BIO.
    pub unsafe extern "C" fn OPENSSL_LH_stats_bio(lh: *const OPENSSL_LHASH, out: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats_bio(lh, out, Stats::Summary) };
    }
}

ffi_export! {
    /// Prints each bucket's chain length to `out` (deprecated).
    ///
    /// # Safety
    /// `lh` is null or a live table; `out` is null or a live BIO.
    pub unsafe extern "C" fn OPENSSL_LH_node_stats_bio(lh: *const OPENSSL_LHASH, out: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats_bio(lh, out, Stats::Nodes) };
    }
}

ffi_export! {
    /// Prints how many buckets are used and the load to `out` (deprecated).
    ///
    /// # Safety
    /// `lh` is null or a live table; `out` is null or a live BIO.
    pub unsafe extern "C" fn OPENSSL_LH_node_usage_stats_bio(lh: *const OPENSSL_LHASH, out: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats_bio(lh, out, Stats::Usage) };
    }
}

ffi_export! {
    /// Prints the item and bucket counts to `fp` (deprecated; the other counters OpenSSL 3.1
    /// dropped print 0).
    ///
    /// # Safety
    /// `lh` is null or a live table; `fp` is null or an open `FILE`.
    pub unsafe extern "C" fn OPENSSL_LH_stats(lh: *const OPENSSL_LHASH, fp: *mut FILE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats(lh, fp, Stats::Summary) };
    }
}

ffi_export! {
    /// Prints each bucket's chain length to `fp` (deprecated).
    ///
    /// # Safety
    /// `lh` is null or a live table; `fp` is null or an open `FILE`.
    pub unsafe extern "C" fn OPENSSL_LH_node_stats(lh: *const OPENSSL_LHASH, fp: *mut FILE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats(lh, fp, Stats::Nodes) };
    }
}

ffi_export! {
    /// Prints how many buckets are used and the load to `fp` (deprecated).
    ///
    /// # Safety
    /// `lh` is null or a live table; `fp` is null or an open `FILE`.
    pub unsafe extern "C" fn OPENSSL_LH_node_usage_stats(lh: *const OPENSSL_LHASH, fp: *mut FILE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_stats(lh, fp, Stats::Usage) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn by_number(data: *const c_void) -> c_ulong {
        // SAFETY: the tables below hold pointers to c_ulong.
        unsafe { *data.cast::<c_ulong>() }
    }

    unsafe extern "C" fn same_number(a: *const c_void, b: *const c_void) -> c_int {
        // SAFETY: as above.
        let a = unsafe { *a.cast::<c_ulong>() };
        // SAFETY: as above.
        let b = unsafe { *b.cast::<c_ulong>() };
        c_int::from(a != b)
    }

    fn hash(text: &CStr) -> c_ulong {
        // SAFETY: a NUL-terminated string.
        unsafe { strhash(text.as_ptr()) }
    }

    fn item(key: &c_ulong) -> *mut c_void {
        ptr::from_ref(key).cast_mut().cast()
    }

    #[test]
    fn strhash_matches_openssl() {
        // Values printed by OpenSSL 3.5's own function.
        assert_eq!(hash(c""), 0);
        assert_eq!(hash(c"a"), 124_608);
        assert_eq!(hash(c"apple"), 3_220_199_158);
        assert_eq!(hash(c"The quick brown fox"), 3_383_893_823);
    }

    #[test]
    fn grows_and_shrinks_keeping_every_item() {
        let keys: Vec<c_ulong> = (0..500).map(|i| i * 7).collect();
        // SAFETY: valid callbacks.
        let lh = unsafe { OPENSSL_LH_new(Some(by_number), Some(same_number)) };
        for key in &keys {
            // SAFETY: a live table; the items outlive it.
            assert!(unsafe { OPENSSL_LH_insert(lh, item(key)) }.is_null());
        }
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_LH_num_items(lh) }, 500);
        // SAFETY: as above.
        let grown = unsafe { table(lh) }.unwrap().read().num_nodes;
        assert!(grown > MIN_NODES);
        for key in keys.iter().step_by(2) {
            // SAFETY: as above.
            assert_eq!(unsafe { OPENSSL_LH_delete(lh, item(key)) }, item(key));
        }
        for (i, key) in keys.iter().enumerate() {
            // SAFETY: as above.
            let found = unsafe { OPENSSL_LH_retrieve(lh, item(key)) };
            assert_eq!(found.is_null(), i % 2 == 0);
        }
        let mut seen = 0usize;
        // SAFETY: as above.
        unsafe { doall(lh, |_| seen += 1) };
        assert_eq!(seen, 250);
        // SAFETY: as above.
        unsafe { OPENSSL_LH_free(lh) };
    }

    /// docs/DEVIATIONS.md: a doall callback that deletes the next item in the chain, which
    /// OpenSSL would then visit through freed memory. The walk stops that chain instead.
    #[test]
    fn deleting_the_next_item_during_doall_is_safe() {
        use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
        static TABLE: AtomicPtr<OPENSSL_LHASH> = AtomicPtr::new(ptr::null_mut());
        static VISITS: AtomicUsize = AtomicUsize::new(0);
        static KEYS: [c_ulong; 4] = [0, 1, 2, 3];
        unsafe extern "C" fn same_bucket(_: *const c_void) -> c_ulong {
            0
        }
        unsafe extern "C" fn delete_next(data: *mut c_void) {
            VISITS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the table's items are pointers into KEYS.
            let key = unsafe { *data.cast::<c_ulong>() };
            if let Some(next) = KEYS.get(usize::try_from(key + 1).unwrap()) {
                let table = TABLE.load(Ordering::Relaxed);
                // SAFETY: the table is live for the whole walk.
                unsafe { OPENSSL_LH_delete(table, ptr::from_ref(next).cast()) };
            }
        }
        // SAFETY: valid callbacks.
        let lh = unsafe { OPENSSL_LH_new(Some(same_bucket), Some(same_number)) };
        TABLE.store(lh, Ordering::Relaxed);
        for key in &KEYS {
            // SAFETY: a live table; the items outlive it.
            unsafe { OPENSSL_LH_insert(lh, item(key)) };
        }
        // SAFETY: as above.
        unsafe { OPENSSL_LH_set_down_load(lh, 0) };
        // SAFETY: as above.
        unsafe { OPENSSL_LH_doall(lh, Some(delete_next)) };
        assert_eq!(
            VISITS.load(Ordering::Relaxed),
            1,
            "the walk stops at the deleted node"
        );
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_LH_num_items(lh) }, 3);
        // SAFETY: as above.
        unsafe { OPENSSL_LH_free(lh) };
    }

    /// docs/DEVIATIONS.md: doall without thunks calls the function directly, and null
    /// tables are refused.
    #[test]
    fn doall_without_thunks_calls_directly() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static VISITED: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn count(_: *mut c_void) {
            VISITED.fetch_add(1, Ordering::Relaxed);
        }
        let key: c_ulong = 3;
        // SAFETY: valid callbacks.
        let lh = unsafe { OPENSSL_LH_new(Some(by_number), Some(same_number)) };
        // SAFETY: a live table; the item outlives it.
        unsafe { OPENSSL_LH_insert(lh, item(&key)) };
        // SAFETY: as above.
        unsafe { OPENSSL_LH_doall(lh, Some(count)) };
        // SAFETY: as above.
        unsafe { OPENSSL_LH_doall(lh, None) };
        assert_eq!(VISITED.load(Ordering::Relaxed), 1);
        // SAFETY: as above.
        unsafe { OPENSSL_LH_free(lh) };
        // SAFETY: a null table is the case under test.
        assert!(unsafe { OPENSSL_LH_insert(ptr::null_mut(), ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_LH_get_down_load(ptr::null()) }, 0);
    }
}
