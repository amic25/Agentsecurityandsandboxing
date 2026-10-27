//! The Linux backend: user, mount, pid, net, ipc and uts namespaces plus
//! Landlock and seccomp, all unprivileged.

pub mod init;
pub mod landlock_rules;
pub mod limits;
pub mod mounts;
pub mod relay;
pub mod seccomp;
pub mod sys;

use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Seek, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};

use crate::plan::LaunchPlan;
use crate::probe::{Capabilities, Degradation, Probe};
use crate::{Backend, Error, ExitStatus, SandboxHandle, TimerGuard};

/// The Linux namespaces backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxBackend;

/// UID and GID the command runs as inside the sandbox. Not 0, so that
/// `execve` drops every capability; not the host uid, so file ownership is
/// still mapped correctly through the user namespace.
pub const INNER_UID: u32 = 1000;

fn sysctl(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Try to create the full namespace set in a throwaway child. ~1 ms.
fn can_create_namespaces() -> Result<(), String> {
    // SAFETY-free wrapper: the child only calls _exit, which is
    // async-signal-safe. The probe runs before any threads exist.
    #[allow(unsafe_code)]
    let forked = unsafe { sys::clone_into_namespaces(sys::NEW_NAMESPACES) };
    match forked {
        Ok(sys::Forked::Child) => sys::exit_now(0),
        Ok(sys::Forked::Parent(pid)) => {
            let _ = sys::wait_pid(pid);
            Ok(())
        }
        Err(e) => {
            let mut hints = Vec::new();
            if sysctl("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
                hints.push("set sysctl kernel.unprivileged_userns_clone=1");
            }
            if sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref()
                == Some("1")
            {
                hints.push(
                    "set sysctl kernel.apparmor_restrict_unprivileged_userns=0 (Ubuntu 23.10+)",
                );
            }
            if sysctl("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
                hints.push("set sysctl user.max_user_namespaces=15000");
            }
            let hint = if hints.is_empty() {
                String::new()
            } else {
                format!(" ({})", hints.join("; "))
            };
            Err(format!(
                "cannot create user+mount+pid+net namespaces: {e}{hint}"
            ))
        }
    }
}

/// Does the kernel support seccomp filters?
pub(crate) fn seccomp_available() -> bool {
    fs::read_to_string("/proc/self/status")
        .is_ok_and(|s| s.lines().any(|l| l.starts_with("Seccomp:")))
}

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn probe(&self) -> Probe {
        if let Err(reason) = can_create_namespaces() {
            return Probe::unavailable(reason);
        }
        let landlock_abi = landlock_rules::kernel_abi();
        let seccomp = seccomp_available();
        let cgroup_v2 = limits::own_cgroup_dir().is_some();
        let mut degradations = Vec::new();
        if landlock_abi == 0 {
            degradations.push(Degradation {
                control: "landlock".into(),
                fallback: "mount namespace only".into(),
                reason: "kernel has no Landlock (needs 5.13+ with lsm=landlock)".into(),
            });
        }
        if !seccomp {
            degradations.push(Degradation {
                control: "seccomp".into(),
                fallback: "none; kernel attack surface not reduced".into(),
                reason: "kernel built without seccomp filter support".into(),
            });
        }
        if !cgroup_v2 {
            degradations.push(Degradation {
                control: "cgroup".into(),
                fallback: "rlimits: RLIMIT_AS for memory (address space, approximate), RLIMIT_NPROC for pids; cpu_percent unenforced".into(),
                reason: "no writable cgroup v2 directory for this process".into(),
            });
        }
        Probe::Available {
            capabilities: Capabilities {
                mount_namespace: true,
                pid_namespace: true,
                net_namespace: true,
                landlock_abi,
                seccomp,
                cgroup_v2,
                rlimits: true,
                no_new_privs: true,
                seatbelt: false,
                container_runtime: None,
            },
            degradations,
        }
    }

    fn launch(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error> {
        launch(plan)
    }
}

/// A running Linux sandbox.
pub struct LinuxHandle {
    pid: i32,
    pidfd: OwnedFd,
    timed_out: Arc<AtomicBool>,
    _cgroup: Option<limits::Cgroup>,
    status: Option<ExitStatus>,
}

impl SandboxHandle for LinuxHandle {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn wait(&mut self) -> Result<ExitStatus, Error> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let raw = loop {
            match sys::wait_pid(self.pid) {
                Ok(raw) => break raw,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => {
                    // Forward a termination request from our caller's handler.
                    let sig = sys::PENDING_SIGNAL.swap(0, Ordering::SeqCst);
                    if sig != 0 {
                        let _ = pidfd_send_signal(&self.pidfd, Signal::TERM);
                    }
                }
                Err(e) => return Err(Error::io("waitpid", e)),
            }
        };
        let status = if self.timed_out.load(Ordering::SeqCst) {
            ExitStatus::WallTimeExceeded
        } else {
            match sys::decode_status(raw) {
                ExitStatus::Code(c) if c == init::SETUP_FAILED => {
                    return Err(Error::Setup("init exited during setup".into()))
                }
                other => other,
            }
        };
        self.status = Some(status);
        Ok(status)
    }

    fn kill(&self) -> Result<(), Error> {
        pidfd_send_signal(&self.pidfd, Signal::KILL).map_err(|e| Error::io("kill", e.into()))
    }

    fn kill_after(&self, after: Duration) -> TimerGuard {
        let (tx, rx) = mpsc::channel::<()>();
        let pidfd = self.pidfd.try_clone().ok();
        let flag = Arc::clone(&self.timed_out);
        std::thread::spawn(move || {
            if rx.recv_timeout(after).is_err() {
                flag.store(true, Ordering::SeqCst);
                if let Some(fd) = pidfd {
                    let _ = pidfd_send_signal(&fd, Signal::KILL);
                }
            }
        });
        TimerGuard::new(Some(tx))
    }
}

fn write_id_map(pid: i32, file: &str, content: &str) -> Result<(), Error> {
    let path = format!("/proc/{pid}/{file}");
    fs::write(&path, content).map_err(|e| Error::io(format!("write {path}"), e))
}

/// Spawn the init process in fresh namespaces and hand it the plan.
///
/// One long function on purpose: the order of these steps is the security
/// argument, and splitting them would hide it.
#[allow(clippy::too_many_lines)]
fn launch(plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error> {
    if !plan.root_base.is_dir() {
        return Err(Error::Plan(format!(
            "root_base {} is not a directory",
            plan.root_base.display()
        )));
    }

    // Everything the child needs is prepared before clone so the child does
    // nothing but fexecve.
    let exe = fs::File::open("/proc/self/exe").map_err(|e| Error::io("open /proc/self/exe", e))?;

    let mut plan_file = tempfile::tempfile().map_err(|e| Error::io("plan tempfile", e))?;
    plan_file
        .write_all(plan.to_json()?.as_bytes())
        .map_err(|e| Error::io("write plan", e))?;
    plan_file
        .rewind()
        .map_err(|e| Error::io("rewind plan", e))?;
    let plan_fd =
        sys::dup_inheritable(plan_file.as_fd()).map_err(|e| Error::io("dup plan fd", e))?;

    let (sync_r, sync_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| Error::io("sync pipe", e.into()))?;
    let sync_fd = sys::dup_inheritable(sync_r.as_fd()).map_err(|e| Error::io("dup sync fd", e))?;
    drop(sync_r);

    let (status_r, status_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| Error::io("status pipe", e.into()))?;
    let status_fd =
        sys::dup_inheritable(status_w.as_fd()).map_err(|e| Error::io("dup status fd", e))?;
    drop(status_w);

    let argv: Vec<CString> = [
        "agentkeep",
        "__init",
        "--plan-fd",
        &plan_fd.to_string(),
        "--sync-fd",
        &sync_fd.to_string(),
        "--status-fd",
        &status_fd.to_string(),
    ]
    .iter()
    .map(|s| CString::new(*s).map_err(|_| Error::Plan("NUL in argv".into())))
    .collect::<Result<_, _>>()?;
    let envp: Vec<CString> = Vec::new();

    // Limits via cgroup, when the host lets us; the sandbox falls back to
    // rlimits otherwise.
    let mut limits = plan.limits;
    let cgroup = limits::Cgroup::create(&plan.session_id, &limits).ok();
    if cgroup.is_some() {
        limits.memory = None; // enforced by the cgroup, not RLIMIT_AS
    }
    let mut effective = plan.clone();
    effective.limits = limits;
    if cgroup.is_some() {
        // Rewrite the plan file with the adjusted limits.
        plan_file
            .set_len(0)
            .map_err(|e| Error::io("truncate plan", e))?;
        plan_file
            .rewind()
            .map_err(|e| Error::io("rewind plan", e))?;
        plan_file
            .write_all(effective.to_json()?.as_bytes())
            .map_err(|e| Error::io("write plan", e))?;
        plan_file
            .rewind()
            .map_err(|e| Error::io("rewind plan", e))?;
    }

    // SAFETY-free wrapper around an unsafe clone: the supervisor must be
    // single-threaded here (documented requirement of `launch`), and the
    // child only calls fexecve and _exit.
    #[allow(unsafe_code)]
    let forked = unsafe { sys::clone_into_namespaces(sys::NEW_NAMESPACES) }
        .map_err(|e| Error::io("clone", e))?;
    let pid = match forked {
        sys::Forked::Child => {
            // exec as a non-root uid clears capabilities; the ambient set is
            // the one that survives. Init drops everything before the command
            // starts.
            if sys::raise_ambient_caps(&[sys::CAP_SYS_ADMIN, sys::CAP_NET_ADMIN, sys::CAP_SETPCAP])
                .is_err()
            {
                sys::exit_now(126);
            }
            let _err = sys::fexecve(exe.as_fd(), &argv, &envp);
            sys::exit_now(127);
        }
        sys::Forked::Parent(pid) => pid,
    };
    // Parent: close the child's copies.
    // SAFETY-free: these raw fds were created by dup above and are owned here.
    #[allow(unsafe_code)]
    unsafe {
        drop(OwnedFd::from_raw_fd(plan_fd));
        drop(OwnedFd::from_raw_fd(sync_fd));
        drop(OwnedFd::from_raw_fd(status_fd));
    }
    drop(plan_file);

    let pidfd = pidfd_open(
        Pid::from_raw(pid).ok_or_else(|| Error::Plan("bad pid".into()))?,
        PidfdFlags::empty(),
    )
    .map_err(|e| Error::io("pidfd_open", e.into()))?;

    // uid/gid maps: a single line mapping our own ids to INNER_UID/GID.
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let maps = write_id_map(pid, "setgroups", "deny")
        .and_then(|()| write_id_map(pid, "gid_map", &format!("{} {gid} 1\n", plan.inner_gid)))
        .and_then(|()| write_id_map(pid, "uid_map", &format!("{} {uid} 1\n", plan.inner_uid)));
    if let Err(e) = maps {
        let _ = pidfd_send_signal(&pidfd, Signal::KILL);
        let _ = sys::wait_pid(pid);
        return Err(e);
    }
    if let Some(cg) = &cgroup {
        if let Err(e) = cg.attach(pid) {
            eprintln!("agentkeep: cgroup attach failed, limits fall back to rlimits: {e}");
        }
    }
    // Release init.
    drop(sync_w);

    // Wait for READY or ERR.
    let mut line = String::new();
    BufReader::new(fs::File::from(status_r))
        .read_line(&mut line)
        .map_err(|e| Error::io("read status", e))?;
    let line = line.trim_end();
    if line != "READY" {
        let _ = sys::wait_pid(pid);
        let msg = line.strip_prefix("ERR ").unwrap_or(if line.is_empty() {
            "init exited before reporting (see messages above)"
        } else {
            line
        });
        return Err(Error::Setup(msg.to_string()));
    }

    Ok(Box::new(LinuxHandle {
        pid,
        pidfd,
        timed_out: Arc::new(AtomicBool::new(false)),
        _cgroup: cgroup,
        status: None,
    }))
}

/// Install supervisor-side signal handling: Ctrl-C goes to the sandboxed
/// command through the terminal, SIGTERM and SIGHUP are forwarded by
/// [`SandboxHandle::wait`].
pub fn install_supervisor_signals() {
    sys::ignore_signal(libc::SIGINT);
    sys::record_signal(libc::SIGTERM);
    sys::record_signal(libc::SIGHUP);
}

/// Kept for callers that predate the platform-neutral
/// [`crate::invoked_as_shim`].
pub use crate::invoked_as_shim;
