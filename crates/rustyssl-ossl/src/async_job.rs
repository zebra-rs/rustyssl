//! Asynchronous jobs (`ASYNC_*`): `speed -async_jobs`'s `run_benchmark`, with a Rust closure
//! as each job's function.

use core::ffi::{c_int, c_void};
use core::ptr::NonNull;

use crate::abi::{ASYNC_ERR, ASYNC_FINISH, ASYNC_JOB, ASYNC_NO_JOBS, ASYNC_PAUSE, ASYNC_WAIT_CTX};
use crate::ffi;
use crate::os;

/// `ASYNC_is_capable()`.
pub fn is_capable() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::ASYNC_is_capable() == 1 }
}

/// `ASYNC_init_thread(max, init)`.
pub fn init_thread(max: usize, init: usize) -> bool {
    // SAFETY: plain integer arguments.
    unsafe { ffi::ASYNC_init_thread(max, init) == 1 }
}

/// `ASYNC_cleanup_thread()`.
pub fn cleanup_thread() {
    // SAFETY: no arguments; it frees this thread's pool.
    unsafe { ffi::ASYNC_cleanup_thread() };
}

/// What a job runs: its index's turn of the caller's closure.
struct Payload<'a> {
    f: *const (dyn Fn(usize) -> c_int + 'a),
    index: usize,
}

unsafe extern "C" fn job_main(arg: *mut c_void) -> c_int {
    // SAFETY: arg is the job's copy of a Payload (ASYNC_start_job copies it into memory it
    // allocates, aligned for any type), whose closure outlives the job (Jobs::run).
    let p = unsafe { &*arg.cast::<Payload<'_>>() };
    // SAFETY: as above.
    let f = unsafe { &*p.f };
    // A panic must not unwind into C (or across the job's stack).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(p.index))).unwrap_or(-1)
}

/// Why a run failed, for the caller's message (each is one of upstream's).
pub enum Failure {
    /// `ASYNC_NO_JOBS` or `ASYNC_ERR`: "Failure in the job".
    Job,
    /// More than one descriptor in a wait context.
    TooManyFds,
    /// A descriptor too large for `select` (the largest one).
    MaxFd(c_int),
    /// `select` failed.
    Select,
}

struct Slot {
    job: *mut ASYNC_JOB,
    wait_ctx: NonNull<ASYNC_WAIT_CTX>,
}

/// One wait context, and job, per looparg.
pub struct Jobs {
    slots: Vec<Slot>,
}

impl Drop for Jobs {
    fn drop(&mut self) {
        for s in &self.slots {
            // SAFETY: the wait context is owned here and freed once.
            unsafe { ffi::ASYNC_WAIT_CTX_free(s.wait_ctx.as_ptr()) };
        }
    }
}

impl Jobs {
    /// `n` wait contexts (`ASYNC_WAIT_CTX_new`); `None` if one can't be made.
    pub fn new(n: usize) -> Option<Self> {
        let mut slots = Vec::with_capacity(n);
        for _ in 0..n {
            // SAFETY: no arguments.
            let w = NonNull::new(unsafe { ffi::ASYNC_WAIT_CTX_new() })?;
            slots.push(Slot {
                job: core::ptr::null_mut(),
                wait_ctx: w,
            });
        }
        Some(Jobs { slots })
    }

    /// `ASYNC_start_job` for slot `i`: the status and the job's return value.
    fn start(&mut self, i: usize, f: &dyn Fn(usize) -> c_int) -> (c_int, c_int) {
        let Some(s) = self.slots.get_mut(i) else {
            return (ASYNC_ERR, 0);
        };
        let payload = Payload { f, index: i };
        let mut ret: c_int = 0;
        // SAFETY: s.job is NULL or the slot's paused job; the wait context is live; the
        // payload is copied by the call and its closure outlives every call of run (which
        // never leaves a paused job behind).
        let status = unsafe {
            ffi::ASYNC_start_job(
                &mut s.job,
                s.wait_ctx.as_ptr(),
                &mut ret,
                Some(job_main),
                (&raw const payload).cast_mut().cast(),
                size_of::<Payload<'_>>(),
            )
        };
        (status, ret)
    }

    /// `ASYNC_WAIT_CTX_get_all_fds` of slot `i`: the count, and the descriptor if there is
    /// one; `None` when the call fails.
    fn fds(&self, i: usize) -> Option<(usize, Option<c_int>)> {
        let s = self.slots.get(i)?;
        let mut num = 0usize;
        // SAFETY: the wait context is live; a NULL array asks for the count only.
        if unsafe {
            ffi::ASYNC_WAIT_CTX_get_all_fds(s.wait_ctx.as_ptr(), core::ptr::null_mut(), &mut num)
        } == 0
        {
            return None;
        }
        if num != 1 {
            return Some((num, None));
        }
        let mut fd: c_int = 0;
        // SAFETY: as above; one descriptor fits.
        unsafe { ffi::ASYNC_WAIT_CTX_get_all_fds(s.wait_ctx.as_ptr(), &mut fd, &mut num) };
        Some((num, Some(fd)))
    }

    /// `run_benchmark` with async jobs: `f(i)` is job `i`'s loop, returning its count (-1 on
    /// failure); the total of the counts, or -1. Each failure is reported to `failed` when it
    /// happens, as upstream prints it then.
    ///
    /// Upstream would resume, in the next run, a job a failed run left paused; here such a
    /// job is abandoned instead, as its closure is gone.
    pub fn run(&mut self, f: &dyn Fn(usize) -> c_int, failed: &mut dyn FnMut(Failure)) -> c_int {
        let n = self.slots.len();
        let (mut total, mut num_inprogress, mut error) = (0 as c_int, 0usize, false);
        let mut i = 0;
        while i < n && !error {
            let (status, ret) = self.start(i, f);
            match status {
                ASYNC_PAUSE => num_inprogress += 1,
                ASYNC_FINISH => {
                    if ret == -1 {
                        error = true;
                    } else {
                        total = total.wrapping_add(ret);
                    }
                }
                ASYNC_NO_JOBS | ASYNC_ERR => {
                    failed(Failure::Job);
                    error = true;
                }
                _ => {}
            }
            i += 1;
        }

        // The descriptor upstream's loop reuses when a context has none.
        let mut job_fd: c_int = 0;
        'wait: while num_inprogress > 0 {
            let mut set: Vec<c_int> = Vec::new();
            let mut max_fd: c_int = 0;
            for i in 0..n {
                if self.slots.get(i).is_none_or(|s| s.job.is_null()) {
                    continue;
                }
                match self.fds(i) {
                    Some((num, fd)) if num <= 1 => {
                        if let Some(fd) = fd {
                            job_fd = fd;
                        }
                        set.push(job_fd);
                        max_fd = max_fd.max(job_fd);
                    }
                    _ => {
                        failed(Failure::TooManyFds);
                        error = true;
                        break;
                    }
                }
            }
            if max_fd >= os::fd_setsize() {
                failed(Failure::MaxFd(max_fd));
                error = true;
                break;
            }
            let ready = match os::select_read(&set) {
                Err(e) if e == libc::EINTR => continue,
                Err(_) => {
                    failed(Failure::Select);
                    error = true;
                    break;
                }
                Ok(r) => r,
            };
            if !ready.iter().any(|&r| r) {
                continue;
            }
            let readable = |fd: c_int| set.iter().zip(&ready).any(|(&s, &r)| s == fd && r);
            for i in 0..n {
                if self.slots.get(i).is_none_or(|s| s.job.is_null()) {
                    continue;
                }
                let num = match self.fds(i) {
                    Some((num, fd)) if num <= 1 => {
                        if let Some(fd) = fd {
                            job_fd = fd;
                        }
                        num
                    }
                    _ => {
                        failed(Failure::TooManyFds);
                        error = true;
                        break;
                    }
                };
                if num == 1 && !readable(job_fd) {
                    continue;
                }
                let (status, ret) = self.start(i, f);
                match status {
                    ASYNC_PAUSE => {}
                    ASYNC_FINISH => {
                        if ret == -1 {
                            error = true;
                        } else {
                            total = total.wrapping_add(ret);
                        }
                        num_inprogress -= 1;
                        if let Some(s) = self.slots.get_mut(i) {
                            s.job = core::ptr::null_mut();
                        }
                    }
                    ASYNC_NO_JOBS | ASYNC_ERR => {
                        num_inprogress -= 1;
                        if let Some(s) = self.slots.get_mut(i) {
                            s.job = core::ptr::null_mut();
                        }
                        failed(Failure::Job);
                        error = true;
                    }
                    _ => {}
                }
                if num_inprogress == 0 {
                    break 'wait;
                }
            }
        }
        for s in &mut self.slots {
            s.job = core::ptr::null_mut();
        }
        if error { -1 } else { total }
    }
}
