//! The parts of the macOS backend that execute: probing, launching under
//! `sandbox-exec`, waiting, killing and terminal hand-over.
//!
//! Everything here is compiled only on macOS. It has not been run outside
//! the macOS CI runners; see `docs/limitations.md`.

use std::fs;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::Duration;

use super::profile::{self, MacInputs};
use super::relay::Relay;
use super::session::{self, Layout};
use super::sys;
use crate::plan::LaunchPlan;
use crate::probe::{Capabilities, Degradation, Probe};
use crate::{Backend, Error, ExitStatus, SandboxHandle, TimerGuard};

/// Apple's Seatbelt front end. Always called by absolute path: a `PATH`
/// lookup could be pointed at a look-alike.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The macOS Seatbelt backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosBackend;

fn degradations() -> Vec<Degradation> {
    let d = |control: &str, fallback: &str, reason: &str| Degradation {
        control: control.into(),
        fallback: fallback.into(),
        reason: reason.into(),
    };
    vec![
        d(
            "mount_namespace",
            "Seatbelt path rules: paths outside the policy are visible but reads and writes are refused",
            "macOS has no mount namespaces",
        ),
        d(
            "hardlinks",
            "none beyond refusing hardlink creation by default",
            "Seatbelt rules match paths, not files",
        ),
        d(
            "pid_namespace",
            "signals and process inspection limited to the sandbox by the profile",
            "macOS has no pid namespaces; host processes exist alongside the sandbox",
        ),
        d(
            "net_namespace",
            "Seatbelt allows only the relay port on the shared loopback and the decision socket",
            "macOS has no network namespaces",
        ),
        d(
            "seccomp",
            "none; kernel attack surface not reduced",
            "Seatbelt does not filter system calls",
        ),
        d(
            "memory_limit",
            "none (memory and cpu_percent are not enforced)",
            "macOS does not enforce RLIMIT_AS and has no cgroups",
        ),
        d(
            "pids_limit",
            "RLIMIT_NPROC set to the user's current process count plus `pids` (approximate)",
            "RLIMIT_NPROC counts every process of the user on macOS",
        ),
        d(
            "no_new_privs",
            "setuid programs still run, confined by the profile",
            "macOS has no no_new_privs",
        ),
    ]
}

fn probe() -> Probe {
    if !Path::new(SANDBOX_EXEC).is_file() {
        return Probe::unavailable(format!(
            "{SANDBOX_EXEC} not found; Apple may have removed it. Use the container backend"
        ));
    }
    let out = Command::new(SANDBOX_EXEC)
        .args(["-p", "(version 1)(allow default)", "--", "/usr/bin/true"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) if o.status.success() => Probe::Available {
            capabilities: Capabilities {
                seatbelt: true,
                rlimits: true,
                ..Capabilities::default()
            },
            degradations: degradations(),
        },
        Ok(o) => Probe::unavailable(format!(
            "{SANDBOX_EXEC} refused a trivial profile ({}): {} (a process that is already sandboxed cannot start another sandbox)",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Probe::unavailable(format!("cannot run {SANDBOX_EXEC}: {e}")),
    }
}

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn probe(&self) -> Probe {
        probe()
    }

    fn launch(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error> {
        launch(plan)
    }
}

/// The terminal the session was started from, while the sandbox holds its
/// foreground.
struct Terminal {
    tty: OwnedFd,
    sandbox_pgrp: i32,
    own_pgrp: i32,
}

static TERMINAL: Mutex<Option<Terminal>> = Mutex::new(None);

/// Open the controlling terminal if this process is in its foreground, so
/// the sandbox can be given the foreground in turn.
fn foreground_terminal() -> Option<OwnedFd> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let fd = OwnedFd::from(f);
    (sys::tcgetpgrp(fd.as_fd()).ok()? == sys::getpgrp()).then_some(fd)
}

/// Take the terminal back for an approval prompt. Returns whether it did.
pub(crate) fn take_terminal() -> bool {
    let g = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
    g.as_ref()
        .is_some_and(|t| sys::tcsetpgrp(t.tty.as_fd(), t.own_pgrp).is_ok())
}

/// Give the terminal back to the sandbox after a prompt. A command that
/// tried to read meanwhile was stopped by `SIGTTIN`; continue it.
pub(crate) fn give_terminal_back() {
    let g = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(t) = g.as_ref() {
        let _ = sys::tcsetpgrp(t.tty.as_fd(), t.sandbox_pgrp);
        let _ = sys::killpg(t.sandbox_pgrp, libc::SIGCONT);
    }
}

/// The active Xcode or Command Line Tools developer directory, so the
/// `/usr/bin` stubs (`git`, `clang`, `python3`, `make`) can find their real
/// binaries. For an Xcode bundle the whole `.app` is allowed read-only.
fn developer_dir() -> Option<PathBuf> {
    let target = fs::read_link("/private/var/db/xcode_select_link").ok()?;
    let real = fs::canonicalize(&target).ok()?;
    let app = real
        .ancestors()
        .find(|a| a.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf);
    Some(app.unwrap_or(real))
}

/// Compile the profile once against `/usr/bin/true`, so a profile Seatbelt
/// rejects is reported as a setup error instead of as the command's exit
/// status.
fn validate(profile: &Path) -> Result<(), Error> {
    let out = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(profile)
        .args(["--", "/usr/bin/true"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::io(format!("run {SANDBOX_EXEC}"), e))?;
    if out.status.success() {
        return Ok(());
    }
    Err(Error::Setup(format!(
        "Seatbelt rejected the generated profile {} ({}): {}",
        profile.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

fn nproc_limit(plan: &LaunchPlan) -> Result<Option<u64>, Error> {
    let Some(pids) = plan.limits.pids else {
        return Ok(None);
    };
    let now = sys::user_process_count(sys::getuid())
        .map_err(|e| Error::io("count the user's processes for RLIMIT_NPROC", e))?;
    let want = u64::try_from(now)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(pids));
    let hard = sys::nproc_hard_limit().unwrap_or(u64::MAX);
    Ok(Some(want.min(hard)))
}

/// One long function on purpose: the order of these steps is the security
/// argument. Nothing is started before the profile exists and has compiled.
fn launch(plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error> {
    if !plan.root_base.is_dir() {
        return Err(Error::Plan(format!(
            "root_base {} is not a directory",
            plan.root_base.display()
        )));
    }
    if plan.command.is_empty() {
        return Err(Error::Plan("empty command".into()));
    }
    let layout = Layout::new(&plan.root_base);
    layout
        .create(plan)
        .map_err(|e| Error::io("create session directories", e))?;

    let relay = match &plan.proxy {
        Some(p) => Some(
            Relay::start(p.host_socket.clone())
                .map_err(|e| Error::io("start the loopback relay to the proxy", e))?,
        ),
        None => None,
    };
    let relay_port = relay.as_ref().map(Relay::port);

    let mut terminals: Vec<PathBuf> = Vec::new();
    for fd in 0..=2 {
        if let Some(t) = sys::ttyname(fd) {
            if !terminals.contains(&t) {
                terminals.push(t);
            }
        }
    }
    let mac = MacInputs {
        home: layout.home.clone(),
        tmp: layout.tmp.clone(),
        shim_dir: plan.shim.as_ref().map(|_| layout.shim_dir.clone()),
        relay_port,
        extra_read_only: developer_dir().into_iter().collect(),
        terminals,
    };
    let text = profile::build(plan, &mac, &session::resolve_existing)
        .map_err(|e| Error::Plan(e.to_string()))?;
    layout
        .write_profile(&text)
        .map_err(|e| Error::io("write the Seatbelt profile", e))?;
    validate(&layout.profile)?;

    let env = session::rewrite_env(plan, &layout, relay_port);
    let nproc = nproc_limit(plan)?;

    let terminal = foreground_terminal();
    if terminal.is_some() {
        // Once the sandbox holds the foreground this process is a background
        // job: it must not be stopped for touching the terminal. The child
        // resets both before exec.
        sys::ignore_signal(libc::SIGTTOU);
        sys::ignore_signal(libc::SIGTTIN);
    }

    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-f")
        .arg(&layout.profile)
        .arg("--")
        .args(&plan.command)
        .env_clear()
        .envs(&env)
        .current_dir(&plan.cwd);
    sys::set_child_setup(
        &mut cmd,
        sys::ChildSetup {
            nproc,
            tty: terminal.as_ref().map(AsRawFd::as_raw_fd),
        },
    );
    // `spawn` returns only after the child has run the setup above and
    // exec'd sandbox-exec, so the process group exists from here on.
    let child = cmd
        .spawn()
        .map_err(|e| Error::io(format!("start {SANDBOX_EXEC}"), e))?;
    let pid = i32::try_from(child.id()).map_err(|_| Error::Plan("bad pid".into()))?;
    drop(child);

    if let Some(tty) = terminal {
        let _ = sys::tcsetpgrp(tty.as_fd(), pid);
        *TERMINAL.lock().unwrap_or_else(PoisonError::into_inner) = Some(Terminal {
            tty,
            sandbox_pgrp: pid,
            own_pgrp: sys::getpgrp(),
        });
    }

    Ok(Box::new(MacosHandle {
        pid,
        reaped: Arc::new(Mutex::new(false)),
        timed_out: Arc::new(AtomicBool::new(false)),
        status: None,
        _relay: relay,
    }))
}

/// Install supervisor-side signal handling: Ctrl-C reaches the command
/// through the terminal it holds; SIGTERM and SIGHUP are forwarded to the
/// sandbox's process group by [`SandboxHandle::wait`].
pub fn install_supervisor_signals() {
    sys::ignore_signal(libc::SIGINT);
    sys::record_signal(libc::SIGTERM);
    sys::record_signal(libc::SIGHUP);
}

/// A running macOS sandbox: the command's process, which leads its own
/// process group.
pub struct MacosHandle {
    pid: i32,
    /// Set once the leader has been reaped; after that its id may be reused
    /// and must not be signalled.
    reaped: Arc<Mutex<bool>>,
    timed_out: Arc<AtomicBool>,
    status: Option<ExitStatus>,
    _relay: Option<Relay>,
}

fn kill_group(pgrp: i32, reaped: &Mutex<bool>) -> Result<(), Error> {
    let done = reaped.lock().unwrap_or_else(PoisonError::into_inner);
    if *done {
        return Ok(());
    }
    match sys::killpg(pgrp, libc::SIGKILL) {
        Err(e) if e.raw_os_error() != Some(libc::ESRCH) => Err(Error::io("kill sandbox", e)),
        _ => Ok(()),
    }
}

/// Job control: the command was stopped (Ctrl-Z). Stop ourselves too so the
/// user's shell gets the terminal back, and resume the command when the
/// shell continues us. Without a terminal there is nobody to hand it to.
fn relay_stop() {
    let has_terminal = {
        let g = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(t) = g.as_ref() {
            let _ = sys::tcsetpgrp(t.tty.as_fd(), t.own_pgrp);
        }
        g.is_some()
    };
    if !has_terminal {
        return;
    }
    let _ = sys::kill(
        i32::try_from(std::process::id()).unwrap_or(0),
        libc::SIGSTOP,
    );
    give_terminal_back();
}

impl MacosHandle {
    fn finish(&self) {
        // The command is done; nothing it started may linger. The group id
        // stays reserved while any member is alive; once the group is empty
        // the call fails with ESRCH. Reuse of the id by an unrelated group
        // in the microseconds since the leader was reaped would need the
        // pid counter to wrap around to exactly this value.
        let _ = sys::killpg(self.pid, libc::SIGKILL);
        *self.reaped.lock().unwrap_or_else(PoisonError::into_inner) = true;
        if let Some(t) = TERMINAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = sys::tcsetpgrp(t.tty.as_fd(), t.own_pgrp);
        }
    }
}

impl SandboxHandle for MacosHandle {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn wait(&mut self) -> Result<ExitStatus, Error> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let raw = loop {
            match sys::waitpid(self.pid, libc::WUNTRACED) {
                Ok(raw) if sys::stopped(raw) => relay_stop(),
                Ok(raw) => break raw,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => {
                    let sig = sys::PENDING_SIGNAL.swap(0, Ordering::SeqCst);
                    if sig != 0 {
                        let _ = sys::killpg(self.pid, libc::SIGTERM);
                    }
                }
                Err(e) => {
                    self.finish();
                    return Err(Error::io("waitpid", e));
                }
            }
        };
        self.finish();
        let status = if self.timed_out.load(Ordering::SeqCst) {
            ExitStatus::WallTimeExceeded
        } else {
            sys::decode_status(raw)
        };
        self.status = Some(status);
        Ok(status)
    }

    fn kill(&self) -> Result<(), Error> {
        kill_group(self.pid, &self.reaped)
    }

    fn kill_after(&self, after: Duration) -> TimerGuard {
        let (tx, rx) = mpsc::channel::<()>();
        let pid = self.pid;
        let reaped = Arc::clone(&self.reaped);
        let flag = Arc::clone(&self.timed_out);
        std::thread::spawn(move || {
            if rx.recv_timeout(after).is_err() {
                flag.store(true, Ordering::SeqCst);
                let _ = kill_group(pid, &reaped);
            }
        });
        TimerGuard::new(Some(tx))
    }
}

impl Drop for MacosHandle {
    fn drop(&mut self) {
        // Never leave a sandbox running behind a supervisor that gave up.
        if self.status.is_none() {
            let _ = kill_group(self.pid, &self.reaped);
            let _ = sys::waitpid(self.pid, 0);
            self.finish();
        }
    }
}
