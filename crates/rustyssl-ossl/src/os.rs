//! What the commands need from the operating system beyond `std`, as upstream's apps use it:
//! `SIGALRM` timers, process CPU times, `fork` (with a pipe, or for `http_server.c`'s
//! responders), `wait`, signals, and `mlock` (Unix).

use core::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// `run` of `speed.c`: set when a timed run starts, cleared by `SIGALRM`.
static RUNNING: AtomicBool = AtomicBool::new(false);

extern "C" fn alarmed(_sig: c_int) {
    // Async-signal-safe: an atomic store, and re-installing the handler as upstream does.
    RUNNING.store(false, Ordering::SeqCst);
    // SAFETY: signal(2) is async-signal-safe; the handler is a valid extern "C" fn.
    unsafe { libc::signal(libc::SIGALRM, alarmed as *const () as libc::sighandler_t) };
}

/// `signal(SIGALRM, alarmed)`: from now on an alarm clears [`running`].
pub fn catch_alarm() {
    // SAFETY: the handler only does async-signal-safe work.
    unsafe { libc::signal(libc::SIGALRM, alarmed as *const () as libc::sighandler_t) };
}

/// `alarm(secs)`; 0 cancels the pending alarm.
pub fn alarm(secs: u32) {
    // SAFETY: alarm(2) takes any value.
    unsafe { libc::alarm(secs) };
}

/// Whether the timed run goes on (no alarm since [`set_running`]).
pub fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Starts (or stops) a timed run.
pub fn set_running(on: bool) {
    RUNNING.store(on, Ordering::SeqCst);
}

/// `times(&t)`: the elapsed clock and the process's user CPU time, in clock ticks.
pub fn times() -> (i64, i64) {
    let mut t = libc::tms {
        tms_utime: 0,
        tms_stime: 0,
        tms_cutime: 0,
        tms_cstime: 0,
    };
    // SAFETY: t is a valid out-parameter.
    let now = unsafe { libc::times(&mut t) };
    (to_i64(now), to_i64(t.tms_utime))
}

/// `sysconf(_SC_CLK_TCK)`: clock ticks per second.
pub fn clock_ticks() -> i64 {
    // SAFETY: sysconf takes any name.
    to_i64(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
}

/// A C integer (`clock_t`, `long`: their types differ by platform) as an `i64`.
fn to_i64<T: TryInto<i64>>(v: T) -> i64 {
    v.try_into().unwrap_or(0)
}

/// `mlock(buf)`, whose result upstream ignores.
pub fn mlock(buf: &[u8]) {
    // SAFETY: the range is a live allocation; mlock only pins its pages.
    unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) };
}

/// `errno`, as `std` sees it.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// What [`fork_to_pipe`] returned in this process.
pub enum Forked {
    /// The child: its standard output is now the pipe.
    Child,
    /// The parent: the pipe's read end.
    Parent(std::fs::File),
}

/// Why [`fork_to_pipe`] failed.
pub enum ForkError {
    /// `pipe` failed.
    Pipe,
    /// The child couldn't put the pipe on its standard output (`dup`).
    Dup,
}

/// `do_multi`'s start of one child: `pipe`, `fork`; the child closes the read end and makes
/// the write end its standard output, the parent closes the write end and keeps the read end.
/// A failed `fork` is treated as the parent, as upstream's `if (fork())` does: its pipe then
/// reads nothing.
pub fn fork_to_pipe() -> Result<Forked, ForkError> {
    let mut fd = [0 as c_int; 2];
    // SAFETY: fd is a valid out-array of two descriptors.
    if unsafe { libc::pipe(fd.as_mut_ptr()) } == -1 {
        return Err(ForkError::Pipe);
    }
    let [rd, wr] = fd;
    // SAFETY: fork(2); the child only does async-signal-safe calls here before returning to
    // ordinary Rust code, and the program has no other threads.
    let pid = unsafe { libc::fork() };
    if pid != 0 {
        // SAFETY: the write end is ours to close.
        unsafe { libc::close(wr) };
        // SAFETY: the read end is a fresh descriptor, owned from here by the File.
        return Ok(Forked::Parent(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(rd)
        }));
    }
    // SAFETY: closing our own descriptors.
    unsafe { libc::close(rd) };
    // SAFETY: as above (standard output, replaced next).
    unsafe { libc::close(1) };
    // SAFETY: as above.
    if unsafe { libc::dup(wr) } == -1 {
        return Err(ForkError::Dup);
    }
    // SAFETY: as above.
    unsafe { libc::close(wr) };
    Ok(Forked::Child)
}

/// How a child ended (`wait`'s status).
pub enum ChildStatus {
    Exited(i32),
    Signaled(i32),
    Other,
}

/// `wait(&status)`: `Err(errno)` when it fails.
pub fn wait() -> Result<ChildStatus, i32> {
    let mut status: c_int = 0;
    // SAFETY: status is a valid out-parameter.
    if unsafe { libc::wait(&mut status) } == -1 {
        return Err(errno());
    }
    Ok(if libc::WIFEXITED(status) {
        ChildStatus::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        ChildStatus::Signaled(libc::WTERMSIG(status))
    } else {
        ChildStatus::Other
    })
}

/// `select` on reading `fds`, blocking: which are readable, or `Err(errno)`.
pub fn select_read(fds: &[c_int]) -> Result<Vec<bool>, i32> {
    // SAFETY: an all-zero fd_set is a valid empty one.
    let mut set: libc::fd_set = unsafe { core::mem::zeroed() };
    let mut max = 0;
    for &fd in fds {
        if fd < 0 || fd >= fd_setsize() {
            return Err(libc::EBADF);
        }
        // SAFETY: fd is within the set's range.
        unsafe { libc::FD_SET(fd, &mut set) };
        max = max.max(fd);
    }
    // SAFETY: set is valid; NULL write/except sets and timeout (block).
    let r = unsafe {
        libc::select(
            max + 1,
            &mut set,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if r == -1 {
        return Err(errno());
    }
    Ok(fds
        .iter()
        // SAFETY: each fd was checked to be within the set's range.
        .map(|&fd| r > 0 && unsafe { libc::FD_ISSET(fd, &set) })
        .collect())
}

/// `FD_SETSIZE`.
pub fn fd_setsize() -> c_int {
    c_int::try_from(libc::FD_SETSIZE).unwrap_or(c_int::MAX)
}

/// What [`fork`] returned in this process.
pub enum Fork {
    /// The child.
    Child,
    /// The parent, with the child's process ID.
    Parent(i32),
}

/// `fork()`: `Err(errno)` when it fails.
pub fn fork() -> Result<Fork, i32> {
    // SAFETY: fork(2); the program has no other threads, so the child's state is consistent.
    match unsafe { libc::fork() } {
        -1 => Err(errno()),
        0 => Ok(Fork::Child),
        pid => Ok(Fork::Parent(pid)),
    }
}

/// `setpgid(0, 0)`: a process group of its own; `Err(errno)` when it fails.
pub fn setpgid_self() -> Result<(), i32> {
    // SAFETY: no pointers.
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(errno());
    }
    Ok(())
}

/// How [`waitpid_any`] found a child: its process ID, its raw status, and how it ended.
pub struct Waited {
    pub pid: i32,
    pub status: i32,
    pub how: ChildStatus,
    /// `WCOREDUMP(status)`.
    pub core_dumped: bool,
}

/// `EINTR`: a call interrupted by a signal.
pub const EINTR: i32 = libc::EINTR;

/// `waitpid(-1, &status, 0)`: `Err(errno)` when it fails (`EINTR` included).
pub fn waitpid_any() -> Result<Waited, i32> {
    let mut status: c_int = 0;
    // SAFETY: status is a valid out-parameter.
    let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
    if pid <= 0 {
        return Err(errno());
    }
    let how = if libc::WIFEXITED(status) {
        ChildStatus::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        ChildStatus::Signaled(libc::WTERMSIG(status))
    } else {
        ChildStatus::Other
    };
    Ok(Waited {
        pid,
        status,
        how,
        core_dumped: libc::WIFSIGNALED(status) && libc::WCOREDUMP(status),
    })
}

/// `kill(pid, SIGTERM)`, whose result upstream ignores.
pub fn terminate(pid: i32) {
    // SAFETY: no pointers.
    unsafe { libc::kill(pid, libc::SIGTERM) };
}

/// `termsig` of `http_server.c`: the termination signal [`catch_termination`]'s handler saw.
static TERMSIG: AtomicI32 = AtomicI32::new(0);

extern "C" fn noteterm(sig: c_int) {
    // Async-signal-safe: an atomic store.
    TERMSIG.store(sig, Ordering::SeqCst);
}

/// `signal(SIGINT, noteterm)` and `signal(SIGTERM, noteterm)`: from now on those signals are
/// noted in [`termination_signal`].
pub fn catch_termination() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only does async-signal-safe work.
        unsafe { libc::signal(sig, noteterm as *const () as libc::sighandler_t) };
    }
}

/// `signal(SIGINT, SIG_DFL)` and `signal(SIGTERM, SIG_DFL)`.
pub fn default_termination() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: restoring the default disposition.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    }
}

/// The signal [`catch_termination`]'s handler noted, or 0.
pub fn termination_signal() -> i32 {
    TERMSIG.load(Ordering::SeqCst)
}

/// `acfd` of `http_server.c`: the client socket an alarm shuts down, or -1.
static ACFD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn socket_timeout(_sig: c_int) {
    let fd = ACFD.load(Ordering::SeqCst);
    if fd != -1 {
        // SAFETY: shutdown(2) is async-signal-safe; a stale descriptor only fails.
        unsafe { libc::shutdown(fd, libc::SHUT_RD) };
    }
}

/// `signal(SIGALRM, socket_timeout)`: from now on an alarm shuts down reading on the socket
/// [`set_alarm_socket`] names.
pub fn catch_alarm_socket_timeout() {
    // SAFETY: the handler only does async-signal-safe work.
    unsafe {
        libc::signal(
            libc::SIGALRM,
            socket_timeout as *const () as libc::sighandler_t,
        )
    };
}

/// Sets `acfd` (-1 for none).
pub fn set_alarm_socket(fd: c_int) {
    ACFD.store(fd, Ordering::SeqCst);
}

/// `strerror(errnum)`.
pub fn strerror(errnum: i32) -> String {
    // SAFETY: strerror takes any number.
    let p = unsafe { libc::strerror(errnum) };
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a valid NUL-terminated string, read before any other call could replace it.
    unsafe { core::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

/// `syslog(LOG_INFO, "%s", msg)`.
pub fn syslog_info(msg: &str) {
    let Ok(m) = std::ffi::CString::new(msg) else {
        return;
    };
    // SAFETY: a constant format taking one NUL-terminated string, which m is.
    unsafe { libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), m.as_ptr()) };
}
