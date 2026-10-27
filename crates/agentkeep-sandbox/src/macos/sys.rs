//! The only module of the macOS backend that contains `unsafe`. Each
//! function wraps one libc call that `std` does not expose, and every block
//! states why it is sound.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::ExitStatus;

/// `PROC_RUID_ONLY` from `<libproc.h>`; not exported by the `libc` crate.
/// Real uid, because that is what `fork` counts against `RLIMIT_NPROC`.
const PROC_RUID_ONLY: u32 = 5;

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Real user id of this process.
pub fn getuid() -> u32 {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// Process group of this process.
pub fn getpgrp() -> i32 {
    // SAFETY: getpgrp has no arguments and cannot fail.
    unsafe { libc::getpgrp() }
}

/// Number of processes currently owned by `uid`. `RLIMIT_NPROC` on macOS
/// counts all of them, not only the sandbox's.
pub fn user_process_count(uid: u32) -> io::Result<usize> {
    // SAFETY: a null buffer with size 0 asks only for the required size.
    let need = unsafe { libc::proc_listpids(PROC_RUID_ONLY, uid, std::ptr::null_mut(), 0) };
    let need = usize::try_from(check(need)?).unwrap_or(0);
    // Room for processes started between the two calls.
    let slots = need / std::mem::size_of::<libc::pid_t>() + 64;
    let mut pids: Vec<libc::pid_t> = vec![0; slots];
    let bytes = libc::c_int::try_from(slots * std::mem::size_of::<libc::pid_t>())
        .map_err(|_| io::Error::other("too many processes"))?;
    // SAFETY: the buffer is valid for `bytes` bytes for the whole call and
    // the kernel writes at most that many.
    let got = unsafe { libc::proc_listpids(PROC_RUID_ONLY, uid, pids.as_mut_ptr().cast(), bytes) };
    let got = usize::try_from(check(got)?).unwrap_or(0) / std::mem::size_of::<libc::pid_t>();
    Ok(pids.iter().take(got).filter(|p| **p > 0).count())
}

/// Path of the terminal device behind `fd`, if it is a terminal.
pub fn ttyname(fd: RawFd) -> Option<PathBuf> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its full length; ttyname_r writes a
    // NUL-terminated string into it or returns an error number.
    let r = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&buf).ok()?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
}

/// Foreground process group of the terminal behind `fd`.
pub fn tcgetpgrp(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: plain ioctl wrapper on a valid, borrowed fd.
    check(unsafe { libc::tcgetpgrp(fd.as_raw_fd()) })
}

/// Make `pgrp` the foreground process group of the terminal behind `fd`.
/// The caller ignores `SIGTTOU`, so this works from the background too.
pub fn tcsetpgrp(fd: BorrowedFd<'_>, pgrp: i32) -> io::Result<()> {
    // SAFETY: plain ioctl wrapper on a valid, borrowed fd.
    check(unsafe { libc::tcsetpgrp(fd.as_raw_fd(), pgrp) }).map(drop)
}

/// Signal every process in a process group.
pub fn killpg(pgrp: i32, sig: libc::c_int) -> io::Result<()> {
    if pgrp <= 1 {
        // Never let a bad id turn into "every process I may signal".
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: killpg has no memory arguments.
    check(unsafe { libc::killpg(pgrp, sig) }).map(drop)
}

/// Signal one process.
pub fn kill(pid: i32, sig: libc::c_int) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: kill has no memory arguments.
    check(unsafe { libc::kill(pid, sig) }).map(drop)
}

/// `waitpid(2)` for one child with `flags`. Returns the raw status.
pub fn waitpid(pid: i32, flags: libc::c_int) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: status is a valid out-pointer for the duration of the call.
    check(unsafe { libc::waitpid(pid, &raw mut status, flags) })?;
    Ok(status)
}

/// Decode a raw wait status.
pub fn decode_status(status: i32) -> ExitStatus {
    if libc::WIFEXITED(status) {
        ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        ExitStatus::Signal(libc::WTERMSIG(status))
    } else {
        ExitStatus::Code(1)
    }
}

/// Did the child stop (job control)?
pub fn stopped(status: i32) -> bool {
    libc::WIFSTOPPED(status)
}

/// Ignore a signal in this process.
pub fn ignore_signal(sig: libc::c_int) {
    // SAFETY: installing SIG_IGN has no handler code to be unsafe.
    unsafe { libc::signal(sig, libc::SIG_IGN) };
}

/// The most recent signal delivered to a handler installed with
/// [`record_signal`], or 0.
pub static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(sig: libc::c_int) {
    PENDING_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Install a handler that records `sig` in [`PENDING_SIGNAL`] and lets
/// blocking calls return `EINTR`, so the wait loop can forward it.
pub fn record_signal(sig: libc::c_int) {
    // SAFETY: sigaction with a zeroed struct is valid; the handler only does
    // an atomic store, which is async-signal-safe. SA_RESTART is absent on
    // purpose so waitpid is interrupted.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = record as extern "C" fn(libc::c_int) as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&raw mut sa.sa_mask);
        libc::sigaction(sig, &raw const sa, std::ptr::null_mut());
    }
}

/// What the child does between `fork` and `exec` of `sandbox-exec`.
#[derive(Debug, Clone, Copy)]
pub struct ChildSetup {
    /// `RLIMIT_NPROC`, if limited.
    pub nproc: Option<u64>,
    /// Terminal to take the foreground of, if the supervisor owned it.
    pub tty: Option<RawFd>,
}

/// Signals whose disposition the supervisor may have changed and which the
/// command must start with at their defaults (an ignored signal survives
/// `exec`).
const RESET: &[libc::c_int] = &[
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

/// Current hard `RLIMIT_NPROC` of this process. An unprivileged process may
/// lower its hard limit but never raise it, so the child's limit must not
/// exceed this.
pub fn nproc_hard_limit() -> io::Result<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid rlimit struct on our stack.
    check(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &raw mut lim) })?;
    Ok(lim.rlim_max)
}

fn set_limit(resource: libc::c_int, value: u64) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit reads a valid rlimit struct from our stack; it is
    // async-signal-safe.
    check(unsafe { libc::setrlimit(resource, &raw const lim) }).map(drop)
}

/// Runs in the forked child. Only async-signal-safe calls: setpgid,
/// tcsetpgrp, signal and setrlimit are all plain system calls.
fn child_setup(setup: ChildSetup) -> io::Result<()> {
    // Own process group, so the wall-clock limit and the end of the session
    // can kill every process the command started (unless one deliberately
    // leaves the group; see docs/limitations.md).
    // SAFETY: setpgid has no memory arguments.
    check(unsafe { libc::setpgid(0, 0) })?;
    if let Some(fd) = setup.tty {
        // The parent ignores SIGTTOU, and the child inherits that until the
        // reset below, so taking the foreground from the background works.
        // SAFETY: getpid and tcsetpgrp have no memory arguments; failure
        // only means the command starts in the background, which the parent
        // retries as well.
        unsafe {
            let _ = libc::tcsetpgrp(fd, libc::getpid());
        }
    }
    for sig in RESET {
        // SAFETY: restoring SIG_DFL installs no handler code.
        unsafe { libc::signal(*sig, libc::SIG_DFL) };
    }
    // Core dumps could carry secrets into a readable directory.
    set_limit(libc::RLIMIT_CORE, 0)?;
    if let Some(n) = setup.nproc {
        set_limit(libc::RLIMIT_NPROC, n)?;
    }
    Ok(())
}

/// Arrange for [`child_setup`] to run in the child spawned by `cmd`.
pub fn set_child_setup(cmd: &mut Command, setup: ChildSetup) {
    // SAFETY: the closure runs between fork and exec in the child, where
    // only async-signal-safe functions may be called. `child_setup` calls
    // nothing but setpgid, getpid, tcsetpgrp, signal and setrlimit, which
    // are all async-signal-safe system calls, allocates nothing and takes
    // no locks; `setup` is a plain Copy value moved into the closure.
    unsafe {
        cmd.pre_exec(move || child_setup(setup));
    }
}
