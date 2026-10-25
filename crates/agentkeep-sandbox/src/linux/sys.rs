//! The only module in agentkeep that contains `unsafe`. Each function wraps
//! one syscall that `std` and `rustix` do not expose in the form we need,
//! and every block states why it is sound.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

/// Namespace flags for [`clone_into_namespaces`].
pub const NEW_NAMESPACES: libc::c_int = libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS;

/// Result of a fork-like clone.
pub enum Forked {
    /// In the parent; holds the child's pid.
    Parent(i32),
    /// In the child.
    Child,
}

/// `clone(2)` with namespace flags, behaving like `fork`.
///
/// # Safety
///
/// The caller must be single-threaded (a multi-threaded fork leaves other
/// threads' locks held in the child) and must, in the child, call only
/// async-signal-safe functions before `exec` or `_exit`.
pub unsafe fn clone_into_namespaces(flags: libc::c_int) -> io::Result<Forked> {
    // SAFETY: raw clone with a null stack behaves like fork: the child
    // continues from here with a copy of the parent's memory. All other
    // arguments are unused with a null stack; passing zeros is valid on both
    // x86_64 and aarch64 regardless of their differing argument order, since
    // every non-flag argument is zero. SIGCHLD makes the child reap-able with
    // waitpid like a normal child.
    let r = libc::syscall(
        libc::SYS_clone,
        libc::c_ulong::try_from(flags).unwrap_or(0) | libc::SIGCHLD as libc::c_ulong,
        0usize,
        0usize,
        0usize,
        0usize,
    );
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if r == 0 {
        Ok(Forked::Child)
    } else {
        Ok(Forked::Parent(i32::try_from(r).unwrap_or(i32::MAX)))
    }
}

/// `fexecve(3)`: execute the program behind an open fd. Does not return on
/// success. Only async-signal-safe work happens here, so it is usable in a
/// freshly cloned child.
pub fn fexecve(fd: BorrowedFd<'_>, argv: &[CString], envp: &[CString]) -> io::Error {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|a| a.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    // SAFETY: both arrays are null-terminated and the CStrings they point to
    // outlive the call. The fd is valid for the lifetime of the borrow.
    unsafe {
        libc::fexecve(fd.as_raw_fd(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    io::Error::last_os_error()
}

/// Exit immediately without running destructors. For use in a cloned child
/// when exec fails.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit is always safe to call; it never returns.
    unsafe { libc::_exit(code) }
}

/// Duplicate an fd *without* `O_CLOEXEC`, so an exec'd child inherits it.
pub fn dup_inheritable(fd: BorrowedFd<'_>) -> io::Result<RawFd> {
    // SAFETY: dup on a valid fd; the result is a new fd we own.
    let r = unsafe { libc::dup(fd.as_raw_fd()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cpath(p: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// `mount(2)`.
pub fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source.map(cpath).transpose()?;
    let target = cpath(target)?;
    let fstype = fstype
        .map(CString::new)
        .transpose()
        .map_err(|_| io::Error::other("NUL"))?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| io::Error::other("NUL"))?;
    let p = |c: &Option<CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: all pointers are either null or point to NUL-terminated strings
    // that live until the call returns. `data` is passed as an opaque string,
    // which is what every filesystem we mount (tmpfs, proc, devpts, sysfs)
    // expects.
    let r = unsafe {
        libc::mount(
            p(&source),
            target.as_ptr(),
            p(&fstype),
            flags,
            p(&data).cast::<libc::c_void>(),
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `umount2(2)`.
pub fn umount2(target: &Path, flags: libc::c_int) -> io::Result<()> {
    let target = cpath(target)?;
    // SAFETY: valid NUL-terminated path.
    let r = unsafe { libc::umount2(target.as_ptr(), flags) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `pivot_root(2)`.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> io::Result<()> {
    let new_root = cpath(new_root)?;
    let put_old = cpath(put_old)?;
    // SAFETY: two valid NUL-terminated paths; no pointers retained.
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Mount flags currently in effect on the filesystem at `path`, translated
/// from `statvfs` `ST_*` bits to `MS_*` bits. Needed because a user
/// namespace may not clear flags locked by the parent when remounting a bind.
pub fn locked_mount_flags(path: &Path) -> io::Result<libc::c_ulong> {
    let c = cpath(path)?;
    // SAFETY: statvfs writes into a zeroed, correctly sized struct.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statvfs(c.as_ptr(), &raw mut st) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let f = st.f_flag as libc::c_ulong;
    let mut out = 0;
    for (st_flag, ms_flag) in [
        (libc::ST_RDONLY, libc::MS_RDONLY),
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if f & (st_flag as libc::c_ulong) != 0 {
            out |= ms_flag;
        }
    }
    Ok(out)
}

/// The Landlock ABI version the kernel supports, or 0 when Landlock is
/// absent or disabled.
pub fn landlock_abi() -> u32 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with the VERSION flag the syscall takes no pointer arguments
    // and only returns a number.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    u32::try_from(r).unwrap_or(0)
}

/// Bring the loopback interface up inside the current network namespace.
pub fn loopback_up() -> io::Result<()> {
    // SAFETY: a plain datagram socket, closed before return.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ifreq is a plain C struct; zero is a valid initial state. The
    // name "lo" with its NUL fits comfortably in the 16-byte name field.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo\0") {
        *dst = libc::c_char::try_from(*src).unwrap_or(0);
    }
    ifr.ifr_ifru.ifru_flags =
        libc::c_short::try_from(libc::IFF_UP | libc::IFF_RUNNING).unwrap_or(0);
    // SAFETY: SIOCSIFFLAGS reads an ifreq from the pointer we pass; the
    // struct outlives the call.
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS, &raw const ifr) };
    let err = io::Error::last_os_error();
    // SAFETY: closing the fd we opened above.
    unsafe { libc::close(sock) };
    if r < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Drop every capability from the bounding set so nothing in the sandbox
/// can regain privileges through a file capability or setuid binary, even
/// if `no_new_privs` were somehow missing.
pub fn drop_bounding_capabilities() {
    for cap in 0..libc::c_ulong::from(64u8) {
        // SAFETY: PR_CAPBSET_DROP takes an integer; unknown caps return
        // EINVAL, which we treat as "past the last cap" and ignore.
        let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            break;
        }
    }
    // SAFETY: clearing the ambient set has no arguments.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
}

/// Ignore a signal in this process.
pub fn ignore_signal(sig: libc::c_int) {
    // SAFETY: installing SIG_IGN has no handler code to be unsafe.
    unsafe { libc::signal(sig, libc::SIG_IGN) };
}

/// Restore the default disposition of a signal.
pub fn default_signal(sig: libc::c_int) {
    // SAFETY: installing SIG_DFL has no handler code to be unsafe.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
}

/// The most recent signal delivered to a handler installed with
/// [`record_signal`], or 0.
pub static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(sig: libc::c_int) {
    PENDING_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Install a handler that records `sig` in [`PENDING_SIGNAL`] and lets
/// blocking syscalls return `EINTR`, so a wait loop can forward it.
pub fn record_signal(sig: libc::c_int) {
    // SAFETY: sigaction with a zeroed struct is valid; the handler only
    // performs an atomic store, which is async-signal-safe. SA_RESTART is
    // deliberately absent so waitpid is interrupted.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = record as extern "C" fn(libc::c_int) as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&raw mut sa.sa_mask);
        libc::sigaction(sig, &raw const sa, std::ptr::null_mut());
    }
}

/// Send a signal to a pid, or to every process in the current pid namespace
/// with `pid = -1`.
pub fn kill(pid: i32, sig: libc::c_int) -> io::Result<()> {
    // SAFETY: kill has no memory arguments.
    let r = unsafe { libc::kill(pid, sig) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `waitpid(2)` for any child. Returns `(pid, raw status)`, or `None` when
/// there are no children left.
pub fn wait_any() -> io::Result<Option<(i32, i32)>> {
    let mut status: libc::c_int = 0;
    // SAFETY: status is a valid out-pointer for the duration of the call.
    let r = unsafe { libc::waitpid(-1, &raw mut status, 0) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ECHILD) {
            return Ok(None);
        }
        return Err(e);
    }
    Ok(Some((r, status)))
}

/// `waitpid(2)` for one child.
pub fn wait_pid(pid: i32) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: as above.
    let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

/// Decode a raw wait status.
pub fn decode_status(status: i32) -> crate::ExitStatus {
    if libc::WIFEXITED(status) {
        crate::ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        crate::ExitStatus::Signal(libc::WTERMSIG(status))
    } else {
        crate::ExitStatus::Code(1)
    }
}

/// Name of the program as the kernel sees `argv[0]`, for shim detection.
pub fn argv0_basename(argv0: &CStr) -> String {
    let s = argv0.to_string_lossy().into_owned();
    match Path::new(&s).file_name() {
        Some(f) => f.to_string_lossy().into_owned(),
        None => s,
    }
}

/// Linux capability numbers we need inside the user namespace until setup
/// is done.
pub const CAP_SETPCAP: u32 = 8;
/// See [`CAP_SETPCAP`].
pub const CAP_NET_ADMIN: u32 = 12;
/// See [`CAP_SETPCAP`].
pub const CAP_SYS_ADMIN: u32 = 21;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_3: u32 = 0x2008_0522;

/// Make `caps` survive `execve` by raising them into the ambient set.
///
/// Async-signal-safe: only raw syscalls on stack data, so it may run in a
/// freshly cloned child. Capabilities not currently permitted are skipped.
pub fn raise_ambient_caps(caps: &[u32]) -> io::Result<()> {
    let mut hdr = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget/capset take pointers to the header and a two-element
    // data array for version 3; both live on our stack for the call.
    unsafe {
        if libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) < 0 {
            return Err(io::Error::last_os_error());
        }
        for &cap in caps {
            let (idx, bit) = ((cap / 32) as usize, 1u32 << (cap % 32));
            if data[idx].permitted & bit != 0 {
                data[idx].inheritable |= bit;
            }
        }
        if libc::syscall(libc::SYS_capset, &raw const hdr, data.as_ptr()) < 0 {
            return Err(io::Error::last_os_error());
        }
        for &cap in caps {
            let (idx, bit) = ((cap / 32) as usize, 1u32 << (cap % 32));
            if data[idx].inheritable & bit != 0 {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    libc::c_ulong::from(cap),
                    0,
                    0,
                );
            }
        }
    }
    Ok(())
}

/// Drop every capability: ambient, bounding, then permitted, effective and
/// inheritable. After this, nothing this process execs can regain them.
pub fn drop_all_capabilities() -> io::Result<()> {
    drop_bounding_capabilities();
    let hdr = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: as in raise_ambient_caps; all-zero data clears every set.
    let r = unsafe { libc::syscall(libc::SYS_capset, &raw const hdr, data.as_ptr()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
