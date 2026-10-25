//! PID 1 inside the sandbox.
//!
//! Started by the supervisor through `fexecve` right after `clone` into the
//! new namespaces. It waits for the supervisor to write the uid/gid maps,
//! reads the plan, builds the root, applies limits, Landlock and seccomp,
//! then runs the command and reaps everything until it exits.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};

use rustix::io::{fcntl_setfd, FdFlags};
use rustix::process::{set_parent_process_death_signal, Signal};

use crate::plan::LaunchPlan;

use super::{landlock_rules, limits, mounts, seccomp, sys};

/// Exit code of init when setup fails before the command starts.
pub const SETUP_FAILED: i32 = 125;

fn fd_file(fd: i32) -> File {
    // SAFETY-free: `File::from_raw_fd` is unsafe in std because of ownership
    // transfer; here the fd was created for this process by the supervisor
    // and nothing else owns it. We wrap it to get Read/Write and closing.
    #[allow(unsafe_code)]
    // SAFETY: the supervisor passed this fd number on the command line; it
    // is open, owned solely by us, and not used elsewhere in this process.
    unsafe {
        File::from_raw_fd(fd)
    }
}

/// Entry point for `agentkeep __init`. Never returns.
pub fn main(plan_fd: i32, sync_fd: i32, status_fd: i32) -> ! {
    // Make sure the command never inherits our control fds.
    for fd in [plan_fd, sync_fd, status_fd] {
        // SAFETY-free: borrowing the fd for one fcntl.
        #[allow(unsafe_code)]
        let b = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let _ = fcntl_setfd(b, FdFlags::CLOEXEC);
    }
    let mut status = fd_file(status_fd);

    // The supervisor may have SIGINT ignored; the command must start with
    // default dispositions so Ctrl-C works. Our own handlers go in after it
    // is spawned.
    sys::default_signal(libc::SIGINT);
    sys::default_signal(libc::SIGTERM);
    sys::default_signal(libc::SIGHUP);

    // Die with the supervisor. PID 1 dying kills the whole pid namespace.
    let _ = set_parent_process_death_signal(Some(Signal::KILL));

    let result = (|| -> Result<std::process::Child, String> {
        // Wait for uid/gid maps: the supervisor closes the sync pipe once
        // they are written.
        let mut sync = fd_file(sync_fd);
        let mut buf = [0u8; 1];
        let _ = sync.read(&mut buf);
        drop(sync);

        let mut plan_text = String::new();
        fd_file(plan_fd)
            .read_to_string(&mut plan_text)
            .map_err(|e| format!("read plan: {e}"))?;
        let plan = LaunchPlan::from_json(&plan_text).map_err(|e| e.to_string())?;
        setup_and_spawn(&plan)
    })();

    let mut child = match result {
        Ok(child) => child,
        Err(msg) => {
            let _ = writeln!(status, "ERR {msg}");
            sys::exit_now(SETUP_FAILED);
        }
    };
    let _ = writeln!(status, "READY");
    drop(status);

    // Forward termination requests from the supervisor to the command; let
    // Ctrl-C reach the command directly through the terminal instead.
    sys::record_signal(libc::SIGTERM);
    sys::ignore_signal(libc::SIGINT);
    sys::ignore_signal(libc::SIGHUP);

    let agent_pid = i32::try_from(child.id()).unwrap_or(0);
    let mut agent_status: Option<i32> = None;
    loop {
        let pending = sys::PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
        if pending == libc::SIGTERM {
            let _ = sys::kill(agent_pid, libc::SIGTERM);
        }
        match sys::wait_any() {
            Ok(Some((pid, st))) => {
                if pid == agent_pid {
                    agent_status = Some(st);
                    // The command is done; nothing else may linger.
                    let _ = sys::kill(-1, libc::SIGKILL);
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Ok(None) | Err(_) => break,
        }
    }
    // Keep std from trying to wait again.
    let _ = child.try_wait();
    let code = match agent_status.map(sys::decode_status) {
        Some(crate::ExitStatus::Code(c)) => c,
        Some(crate::ExitStatus::Signal(s)) => 128 + s,
        _ => 1,
    };
    sys::exit_now(code)
}

fn setup_and_spawn(plan: &LaunchPlan) -> Result<std::process::Child, String> {
    let _ = rustix::system::sethostname(plan.hostname.as_bytes());
    sys::loopback_up().map_err(|e| format!("loopback up: {e}"))?;

    mounts::build_root(plan)?;

    // Limits: memory via rlimit only when no cgroup took it (the supervisor
    // tells us through the plan's limits having memory set; it clears it
    // when a cgroup is active).
    limits::apply_rlimits(&plan.limits, true);

    // From here on nothing needs privileges, and the command must not
    // inherit any.
    sys::drop_all_capabilities().map_err(|e| format!("drop capabilities: {e}"))?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;

    if plan.landlock {
        landlock_rules::apply(plan)?;
    }
    if plan.seccomp {
        seccomp::apply()?;
    }

    let (prog, args) = plan.command.split_first().ok_or("empty command")?;
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .env_clear()
        .envs(&plan.env)
        .current_dir(&plan.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.spawn().map_err(|e| format!("exec `{prog}`: {e}"))
}
