//! Asynchronous jobs (`ASYNC_*`, `crypto/async`) and their wait contexts (`ASYNC_WAIT_CTX_*`).
//!
//! rustyssl has no fibres (OpenSSL switches stacks with `makecontext`/`swapcontext`, which no
//! safe Rust can do), so a job runs synchronously to completion on the caller's stack: a job
//! always finishes (`ASYNC_FINISH`), never pauses, and `ASYNC_pause_job` inside one returns at
//! once, as though the job had been resumed straight away. `ASYNC_is_capable()` says so (0),
//! as OpenSSL's builds without an async backend do (`ASYNC_NULL`), but where those can't start
//! a job at all (`ASYNC_NO_JOBS`), here it runs (docs/DEVIATIONS.md). Nothing in rustyssl
//! pauses (there are no engines), so `SSL_MODE_ASYNC` and `ASYNC_start_job` callers get their
//! results; only code that needs a job to suspend until an event (an async engine's hardware
//! completion) sees the difference, as a pause that doesn't wait.
//!
//! The per-thread state is OpenSSL's: the job running (for `ASYNC_get_current_job`), the
//! count of `ASYNC_block_pause`s, and the pool of jobs that `ASYNC_init_thread` sizes and
//! `ASYNC_cleanup_thread` frees.

use core::cell::RefCell;
use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ASYNC_ERR, ASYNC_FINISH, ASYNC_JOB, ASYNC_NO_JOBS, ASYNC_R_INVALID_POOL_SIZE, ASYNC_WAIT_CTX,
    ASYNC_callback_fn, ASYNC_stack_alloc_fn, ASYNC_stack_free_fn, ERR_LIB_ASYNC,
    ERR_R_INTERNAL_ERROR, OPENSSL_INIT_ASYNC, OSSL_LIB_CTX,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::init::OPENSSL_init_crypto;
use crate::libctx::{OSSL_LIB_CTX_set0_default, current};
use crate::mem;

/// The job function `ASYNC_start_job` runs.
type JobFn = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

/// `struct async_job_st`, without the fibre.
struct Job {
    func: JobFn,
    /// The copy of the caller's arguments (`CRYPTO_malloc`), or NULL.
    funcargs: *mut c_void,
    ret: c_int,
    waitctx: *mut ASYNC_WAIT_CTX,
    /// The default library context the job left set, restored around it.
    libctx: *mut OSSL_LIB_CTX,
}

impl Job {
    fn new() -> Box<Self> {
        Box::new(Self {
            func: None,
            funcargs: ptr::null_mut(),
            ret: 0,
            waitctx: ptr::null_mut(),
            libctx: ptr::null_mut(),
        })
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the job's copy of the arguments, or NULL.
        unsafe { mem::release(self.funcargs) };
    }
}

/// `struct async_pool_st`: the jobs ready to run, how many the thread has made, and the most
/// it may (0: no limit).
struct Pool {
    #[allow(
        clippy::vec_box,
        reason = "a job is handed to C by its address, which must not move"
    )]
    jobs: Vec<Box<Job>>,
    curr_size: usize,
    max_size: usize,
}

/// A thread's state: `async_ctx` (the job running and the pause blocks) and the pool.
#[derive(Default)]
struct Thread {
    pool: Option<Pool>,
    currjob: Option<*mut Job>,
    blocked: u32,
}

thread_local! {
    static THREAD: RefCell<Thread> = RefCell::new(Thread::default());
}

/// Runs `f` on the thread's state (None while the thread is exiting). The borrow never spans
/// a job or a callback.
fn with<T>(f: impl FnOnce(&mut Thread) -> T) -> Option<T> {
    THREAD
        .try_with(|t| t.try_borrow_mut().ok().map(|mut t| f(&mut t)))
        .ok()
        .flatten()
}

/// `OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)`.
fn init() -> bool {
    let opts = u64::try_from(OPENSSL_INIT_ASYNC).unwrap_or(0);
    // SAFETY: no settings.
    (unsafe { OPENSSL_init_crypto(opts, ptr::null()) }) != 0
}

/// A job from the thread's pool (made if the pool has room; the pool itself made with the
/// defaults if the thread has none), or None (`ASYNC_NO_JOBS`).
fn pool_job() -> Option<Box<Job>> {
    with(|t| {
        let pool = t.pool.get_or_insert_with(|| Pool {
            jobs: Vec::new(),
            curr_size: 0,
            max_size: 0,
        });
        if let Some(job) = pool.jobs.pop() {
            return Some(job);
        }
        if pool.max_size != 0 && pool.curr_size >= pool.max_size {
            return None;
        }
        pool.curr_size = pool.curr_size.saturating_add(1);
        Some(Job::new())
    })
    .flatten()
}

/// `async_release_job`: back to the pool, its arguments freed.
fn release(mut job: Box<Job>) {
    // SAFETY: the job's copy of the arguments, or NULL.
    unsafe { mem::release(job.funcargs) };
    job.funcargs = ptr::null_mut();
    job.func = None;
    job.waitctx = ptr::null_mut();
    with(|t| match t.pool.as_mut() {
        Some(p) => p.jobs.push(job),
        // The pool went (ASYNC_cleanup_thread inside the job): as OpenSSL, an internal error.
        None => err::raise(ERR_LIB_ASYNC, ERR_R_INTERNAL_ERROR, "async_release_job"),
    });
}

ffi_export! {
    /// Runs `func` with a copy of the `size` octets at `args` (or NULL) as a job, to completion:
    /// `ASYNC_FINISH` with its result in `*ret` and `*job` NULL; `ASYNC_NO_JOBS` if the
    /// thread's pool is exhausted; `ASYNC_ERR` otherwise. Jobs never pause, so `*job` is never
    /// a paused job to resume: one given, or a call from inside a job, is an internal error.
    ///
    /// # Safety
    /// `job` is a slot (holding NULL); `wctx` NULL or a live wait context; `ret` NULL or
    /// writable; `func` a job function; `args` NULL or `size` readable octets.
    pub unsafe extern "C" fn ASYNC_start_job(job: *mut *mut ASYNC_JOB, wctx: *mut ASYNC_WAIT_CTX, ret: *mut c_int, func: JobFn, args: *mut c_void, size: usize) -> c_int
    where failure = ASYNC_ERR, library = ERR_LIB_ASYNC
    {
        if !init() || job.is_null() {
            return ASYNC_ERR;
        }
        let nested = with(|t| t.currjob.is_some()).unwrap_or(true);
        // SAFETY: the caller's slot.
        if nested || !unsafe { job.read() }.is_null() {
            err::raise(ERR_LIB_ASYNC, ERR_R_INTERNAL_ERROR, "ASYNC_start_job");
            // SAFETY: as above.
            unsafe { job.write(ptr::null_mut()) };
            return ASYNC_ERR;
        }
        let Some(mut j) = pool_job() else { return ASYNC_NO_JOBS };
        if !args.is_null() && size > 0 {
            j.funcargs = mem::alloc(size);
            if j.funcargs.is_null() {
                release(j);
                return ASYNC_ERR;
            }
            // SAFETY: the caller's `size` octets into the copy of that size.
            unsafe { ptr::copy_nonoverlapping(args.cast::<u8>(), j.funcargs.cast::<u8>(), size) };
        }
        j.func = func;
        j.waitctx = wctx;
        let raw: *mut Job = Box::into_raw(j);
        with(|t| t.currjob = Some(raw));
        let saved = current();
        // SAFETY: the job, owned here until it's back in a box.
        let f = unsafe { (*raw).func };
        // SAFETY: as above.
        let a = unsafe { (*raw).funcargs };
        // The job runs with no state borrowed: it may call any ASYNC function.
        let r = match f {
            // SAFETY: the caller's job function with the copy of its arguments.
            Some(f) => unsafe { f(a) },
            None => 0,
        };
        // SAFETY: as above.
        unsafe { (*raw).ret = r };
        // As OpenSSL does around a fibre: the default library context the job set is kept
        // with the job, and the caller's set back.
        // SAFETY: the caller's default, live while it's the default.
        let left = unsafe { OSSL_LIB_CTX_set0_default(saved) };
        // SAFETY: as above.
        unsafe { (*raw).libctx = left };
        // As OpenSSL's per-thread count, pause blocks left by the job stay.
        with(|t| t.currjob = None);
        // SAFETY: the box made above, not referenced elsewhere now.
        let j = unsafe { Box::from_raw(raw) };
        if !ret.is_null() {
            // SAFETY: the caller's slot.
            unsafe { ret.write(j.ret) };
        }
        release(j);
        // SAFETY: as above.
        unsafe { job.write(ptr::null_mut()) };
        ASYNC_FINISH
    }
}

ffi_export! {
    /// Returns from a pause at once: 1 (outside a job, with pauses blocked, or in a job, which
    /// can't suspend; the wait context's added and deleted descriptors then settle, as after
    /// a resumption).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_pause_job() -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        let w = with(|t| match (t.currjob, t.blocked) {
            // SAFETY: the running job, live while it runs.
            (Some(j), 0) => unsafe { (*j).waitctx },
            _ => ptr::null_mut(),
        })
        .unwrap_or(ptr::null_mut());
        // SAFETY: the job's wait context, NULL or live while the job runs.
        unsafe { reset_counts(w) };
        1
    }
}

ffi_export! {
    /// The job running on this thread, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_get_current_job() -> *mut ASYNC_JOB
    where failure = ptr::null_mut(), library = ERR_LIB_ASYNC
    {
        if !init() {
            return ptr::null_mut();
        }
        with(|t| t.currjob).flatten().map_or(ptr::null_mut(), |j| j.cast())
    }
}

ffi_export! {
    /// The job's wait context (NULL for none, or for NULL, where OpenSSL crashes).
    ///
    /// # Safety
    /// `job` is NULL or the running job.
    pub unsafe extern "C" fn ASYNC_get_wait_ctx(job: *mut ASYNC_JOB) -> *mut ASYNC_WAIT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        unsafe { job.cast::<Job>().as_ref() }.map_or(ptr::null_mut(), |j| j.waitctx)
    }
}

ffi_export! {
    /// Blocks pausing in the running job (nothing outside one).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_block_pause()
    where failure = (), library = ERR_LIB_ASYNC
    {
        if !init() {
            return;
        }
        with(|t| {
            if t.currjob.is_some() {
                t.blocked = t.blocked.saturating_add(1);
            }
        });
    }
}

ffi_export! {
    /// Undoes one `ASYNC_block_pause` in the running job (nothing outside one).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_unblock_pause()
    where failure = (), library = ERR_LIB_ASYNC
    {
        if !init() {
            return;
        }
        with(|t| {
            if t.currjob.is_some() {
                t.blocked = t.blocked.saturating_sub(1);
            }
        });
    }
}

ffi_export! {
    /// Gives the thread a pool of at most `max_size` jobs (0: no limit), `init_size` of them
    /// made now: 1, or 0 (`ASYNC_R_INVALID_POOL_SIZE` if `init_size > max_size`). A pool the
    /// thread had is replaced (OpenSSL leaks it).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_init_thread(max_size: usize, init_size: usize) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        if init_size > max_size {
            err::raise(ERR_LIB_ASYNC, ASYNC_R_INVALID_POOL_SIZE, "ASYNC_init_thread");
            return 0;
        }
        if !init() {
            return 0;
        }
        let jobs: Vec<Box<Job>> = (0..init_size).map(|_| Job::new()).collect();
        let pool = Pool { jobs, curr_size: init_size, max_size };
        c_int::from(with(|t| t.pool = Some(pool)).is_some())
    }
}

ffi_export! {
    /// Frees the thread's pool and state.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_cleanup_thread()
    where failure = (), library = ERR_LIB_ASYNC
    {
        if !init() {
            return;
        }
        let pool = with(|t| {
            t.blocked = 0;
            t.pool.take()
        });
        // The jobs are dropped outside the borrow.
        drop(pool);
    }
}

ffi_export! {
    /// 0: jobs can't pause here (they run to completion).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_is_capable() -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        0
    }
}

ffi_export! {
    /// 0, as OpenSSL's builds without fibres: jobs have no stacks to allocate.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_set_mem_functions(_alloc_fn: ASYNC_stack_alloc_fn, _free_fn: ASYNC_stack_free_fn) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        0
    }
}

ffi_export! {
    /// NULL in each slot given, as OpenSSL's builds without fibres.
    ///
    /// # Safety
    /// `alloc_fn` and `free_fn` are NULL or writable.
    pub unsafe extern "C" fn ASYNC_get_mem_functions(alloc_fn: *mut ASYNC_stack_alloc_fn, free_fn: *mut ASYNC_stack_free_fn)
    where failure = (), library = ERR_LIB_ASYNC
    {
        if !alloc_fn.is_null() {
            // SAFETY: the caller's slot.
            unsafe { alloc_fn.write(None) };
        }
        if !free_fn.is_null() {
            // SAFETY: as above.
            unsafe { free_fn.write(None) };
        }
    }
}

/// A wait descriptor's cleanup function.
type Cleanup = Option<unsafe extern "C" fn(*mut ASYNC_WAIT_CTX, *const c_void, c_int, *mut c_void)>;

/// `struct fd_lookup_st`.
struct Fd {
    key: *const c_void,
    fd: c_int,
    custom_data: *mut c_void,
    cleanup: Cleanup,
    add: bool,
    del: bool,
}

/// `struct async_wait_ctx_st`: the descriptors (newest first), the counts added and deleted
/// since the job last resumed, the callback, and the status.
struct WaitCtx {
    fds: Vec<Fd>,
    numadd: usize,
    numdel: usize,
    callback: ASYNC_callback_fn,
    callback_arg: *mut c_void,
    status: c_int,
}

/// The wait context behind a handle.
///
/// # Safety
/// `ctx` is NULL or a live wait context, not otherwise borrowed.
unsafe fn wait<'a>(ctx: *mut ASYNC_WAIT_CTX) -> Option<&'a mut WaitCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<WaitCtx>().as_mut() }
}

/// `async_wait_ctx_reset_counts`: zero counts; deleted descriptors go, added ones settle.
///
/// # Safety
/// `ctx` is NULL or a live wait context.
unsafe fn reset_counts(ctx: *mut ASYNC_WAIT_CTX) {
    // SAFETY: the caller's guarantee.
    let Some(w) = (unsafe { wait(ctx) }) else {
        return;
    };
    w.numadd = 0;
    w.numdel = 0;
    w.fds.retain(|f| !f.del);
    for f in &mut w.fds {
        f.add = false;
    }
}

ffi_export! {
    /// A new, empty wait context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_new() -> *mut ASYNC_WAIT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_ASYNC
    {
        let w = WaitCtx {
            fds: Vec::new(),
            numadd: 0,
            numdel: 0,
            callback: None,
            callback_arg: ptr::null_mut(),
            status: 0,
        };
        Box::into_raw(Box::new(w)).cast()
    }
}

ffi_export! {
    /// Frees the wait context, first calling the cleanup of each descriptor not marked
    /// deleted (newest first); nothing for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live wait context, not used after (the cleanups may still read it).
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_free(ctx: *mut ASYNC_WAIT_CTX)
    where failure = (), library = ERR_LIB_ASYNC
    {
        if ctx.is_null() {
            return;
        }
        // The cleanups run with the context still allocated and nothing borrowed.
        let mut i = 0usize;
        loop {
            // SAFETY: the caller's context.
            let Some(w) = (unsafe { wait(ctx) }) else { return };
            let Some(f) = w.fds.get(i) else { break };
            let (del, cleanup, key, fd, data) = (f.del, f.cleanup, f.key, f.fd, f.custom_data);
            i = i.saturating_add(1);
            if !del && let Some(c) = cleanup {
                // SAFETY: the application's cleanup, with what it registered.
                unsafe { c(ctx, key, fd, data) };
            }
        }
        // SAFETY: the box made by ASYNC_WAIT_CTX_new.
        drop(unsafe { Box::from_raw(ctx.cast::<WaitCtx>()) });
    }
}

ffi_export! {
    /// Adds descriptor `fd` under `key` (with `custom_data` and `cleanup`): 1.
    ///
    /// # Safety
    /// `ctx` is a live wait context (as in OpenSSL, NULL crashes; here 0).
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_wait_fd(ctx: *mut ASYNC_WAIT_CTX, key: *const c_void, fd: c_int, custom_data: *mut c_void, cleanup: Cleanup) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        w.fds.insert(0, Fd { key, fd, custom_data, cleanup, add: true, del: false });
        w.numadd = w.numadd.saturating_add(1);
        1
    }
}

ffi_export! {
    /// The descriptor and custom data under `key` (not deleted): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live wait context; `fd` and `custom_data` writable.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_fd(ctx: *mut ASYNC_WAIT_CTX, key: *const c_void, fd: *mut c_int, custom_data: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        let Some(f) = w.fds.iter().find(|f| !f.del && f.key == key) else { return 0 };
        if !fd.is_null() {
            // SAFETY: the caller's slot.
            unsafe { fd.write(f.fd) };
        }
        if !custom_data.is_null() {
            // SAFETY: as above.
            unsafe { custom_data.write(f.custom_data) };
        }
        1
    }
}

ffi_export! {
    /// The descriptors not deleted (newest first) into `fd` if it isn't NULL, and their count
    /// in `*numfds`: 1.
    ///
    /// # Safety
    /// `ctx` is a live wait context; `fd` NULL or room for the descriptors; `numfds` writable.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_all_fds(ctx: *mut ASYNC_WAIT_CTX, fd: *mut c_int, numfds: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        let mut n = 0usize;
        for f in w.fds.iter().filter(|f| !f.del) {
            if !fd.is_null() {
                // SAFETY: the caller's room for every descriptor.
                let slot = unsafe { fd.add(n) };
                // SAFETY: as above.
                unsafe { slot.write(f.fd) };
            }
            n = n.saturating_add(1);
        }
        if !numfds.is_null() {
            // SAFETY: the caller's slot.
            unsafe { numfds.write(n) };
        }
        1
    }
}

ffi_export! {
    /// The counts of descriptors added and deleted since the job last resumed, and (where the
    /// arrays aren't NULL) those descriptors, leaving out ones both added and deleted: 1.
    ///
    /// # Safety
    /// `ctx` is a live wait context; the counts writable; the arrays NULL or room for them.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_changed_fds(ctx: *mut ASYNC_WAIT_CTX, addfd: *mut c_int, numaddfds: *mut usize, delfd: *mut c_int, numdelfds: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        if !numaddfds.is_null() {
            // SAFETY: the caller's slot.
            unsafe { numaddfds.write(w.numadd) };
        }
        if !numdelfds.is_null() {
            // SAFETY: as above.
            unsafe { numdelfds.write(w.numdel) };
        }
        let (mut a, mut d) = (0usize, 0usize);
        for f in &w.fds {
            if f.del && !f.add && !delfd.is_null() {
                // SAFETY: the caller's room for the deleted descriptors.
                let slot = unsafe { delfd.add(d) };
                // SAFETY: as above.
                unsafe { slot.write(f.fd) };
                d = d.saturating_add(1);
            }
            if f.add && !f.del && !addfd.is_null() {
                // SAFETY: the caller's room for the added descriptors.
                let slot = unsafe { addfd.add(a) };
                // SAFETY: as above.
                unsafe { slot.write(f.fd) };
                a = a.saturating_add(1);
            }
        }
        1
    }
}

ffi_export! {
    /// Clears the descriptor under `key`: one just added goes (its cleanup not called), an
    /// older one is marked deleted: 1, or 0 if there's none.
    ///
    /// # Safety
    /// `ctx` is a live wait context.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_clear_fd(ctx: *mut ASYNC_WAIT_CTX, key: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        let Some(i) = w.fds.iter().position(|f| !f.del && f.key == key) else { return 0 };
        let Some(f) = w.fds.get_mut(i) else { return 0 };
        if f.add {
            w.fds.remove(i);
            w.numadd = w.numadd.saturating_sub(1);
        } else {
            f.del = true;
            w.numdel = w.numdel.saturating_add(1);
        }
        1
    }
}

ffi_export! {
    /// Sets the callback that tells the application a job can resume: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live wait context.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_callback(ctx: *mut ASYNC_WAIT_CTX, callback: ASYNC_callback_fn, callback_arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        w.callback = callback;
        w.callback_arg = callback_arg;
        1
    }
}

ffi_export! {
    /// The callback and its argument: 1, or 0 if none is set.
    ///
    /// # Safety
    /// `ctx` is a live wait context; the slots writable.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_callback(ctx: *mut ASYNC_WAIT_CTX, callback: *mut ASYNC_callback_fn, callback_arg: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        if w.callback.is_none() {
            return 0;
        }
        if !callback.is_null() {
            // SAFETY: the caller's slot.
            unsafe { callback.write(w.callback) };
        }
        if !callback_arg.is_null() {
            // SAFETY: as above.
            unsafe { callback_arg.write(w.callback_arg) };
        }
        1
    }
}

ffi_export! {
    /// Sets the job's status for the application: 1.
    ///
    /// # Safety
    /// `ctx` is a live wait context.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_status(ctx: *mut ASYNC_WAIT_CTX, status: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        let Some(w) = (unsafe { wait(ctx) }) else { return 0 };
        w.status = status;
        1
    }
}

ffi_export! {
    /// The status set (0, `ASYNC_STATUS_UNSUPPORTED`, at first).
    ///
    /// # Safety
    /// `ctx` is a live wait context.
    pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_status(ctx: *mut ASYNC_WAIT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_ASYNC
    {
        // SAFETY: the caller's guarantee.
        unsafe { wait(ctx) }.map_or(0, |w| w.status)
    }
}
