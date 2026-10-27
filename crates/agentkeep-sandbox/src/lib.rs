//! Sandbox backends.
//!
//! A [`Backend`] turns a backend-agnostic [`LaunchPlan`] into a confined
//! process tree. Each backend reports what it can enforce through
//! [`Capabilities`]; the caller compares that with the policy and refuses to
//! run (or runs with recorded degradations) when they disagree.
//!
//! Backends: `linux` (namespaces, Landlock, seccomp; preferred on Linux),
//! `container` (Podman or Docker through their CLI, Linux hosts) and
//! `macos` (Seatbelt via `sandbox-exec`). The macOS profile generator is
//! portable and tested on every platform; probing and launching it needs
//! macOS. On other operating systems no backend is compiled in yet and
//! `agentkeep run` says so.
//!
//! `unsafe` is confined to `linux::sys` and `macos::sys` (plus a few marked
//! blocks in the Linux launcher); every block carries a `SAFETY` comment.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod plan;
pub mod probe;

#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;

use std::fmt;
use std::time::Duration;

pub use plan::{LaunchPlan, Limits, Mount, MountMode, ProxyPlan, ShimConfig};
pub use probe::{Capabilities, Degradation, Probe};

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors from launching or supervising a sandbox.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The backend cannot run on this host.
    #[error("backend `{backend}` unavailable: {reason}")]
    Unavailable {
        /// Backend name.
        backend: &'static str,
        /// Why, with a hint on how to fix it where possible.
        reason: String,
    },
    /// A step of the launch failed.
    #[error("{step}: {source}")]
    Io {
        /// What was being done.
        step: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The plan could not be serialised or read.
    #[error("launch plan: {0}")]
    Plan(String),
    /// The sandbox init process reported a setup failure.
    #[error("sandbox setup failed: {0}")]
    Setup(String),
}

impl Error {
    /// Attach a step description to an I/O error.
    pub fn io(step: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            step: step.into(),
            source,
        }
    }
}

/// How the sandboxed command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Exited normally with this code.
    Code(i32),
    /// Killed by this signal.
    Signal(i32),
    /// Killed by agentkeep because the wall-clock limit was hit.
    WallTimeExceeded,
}

impl ExitStatus {
    /// Shell-style exit code: the code itself, or 128 + signal.
    pub fn shell_code(self) -> i32 {
        match self {
            Self::Code(c) => c,
            Self::Signal(s) => 128 + s,
            Self::WallTimeExceeded => 124,
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(c) => write!(f, "exit code {c}"),
            Self::Signal(s) => write!(f, "killed by signal {s}"),
            Self::WallTimeExceeded => write!(f, "wall-clock limit exceeded"),
        }
    }
}

/// Cancels a pending [`SandboxHandle::kill_after`] timer when dropped.
pub struct TimerGuard {
    cancel: Option<std::sync::mpsc::Sender<()>>,
}

impl TimerGuard {
    /// A guard that cancels through `cancel`, or does nothing when `None`.
    pub fn new(cancel: Option<std::sync::mpsc::Sender<()>>) -> Self {
        Self { cancel }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

/// A running sandbox.
pub trait SandboxHandle: Send {
    /// Host PID of the sandbox's init process.
    fn pid(&self) -> i32;
    /// Block until the sandbox exits.
    fn wait(&mut self) -> Result<ExitStatus, Error>;
    /// Kill everything in the sandbox.
    fn kill(&self) -> Result<(), Error>;
    /// Kill after `after`, from another thread. Returns a guard that cancels
    /// the timer when dropped.
    fn kill_after(&self, after: Duration) -> TimerGuard;
}

/// A sandbox implementation.
pub trait Backend: Send + Sync {
    /// Short name as used in policies and logs.
    fn name(&self) -> &'static str;
    /// Can this backend run here, and how well?
    fn probe(&self) -> Probe;
    /// Launch a plan. The returned handle owns the sandbox.
    fn launch(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error>;
}

/// UID and GID the command runs as inside a namespace-based sandbox.
pub fn linux_inner_uid() -> u32 {
    1000
}

/// All backends compiled into this build, in auto-selection order.
pub fn backends() -> Vec<Box<dyn Backend>> {
    #[cfg(target_os = "linux")]
    {
        // `auto` takes the first available one: namespaces need no daemon
        // and start in milliseconds, so they win when the kernel allows them.
        vec![
            Box::new(linux::LinuxBackend),
            Box::new(container::ContainerBackend::default()),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![Box::new(macos::MacosBackend)]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// True when `argv[0]` names something other than agentkeep itself, which
/// means we were started through a command shim (a symlink to the agentkeep
/// binary named after the command). Returns the command name.
pub fn invoked_as_shim(argv0: &str) -> Option<String> {
    let base = std::path::Path::new(argv0)
        .file_name()?
        .to_str()?
        .to_string();
    (base != "agentkeep" && !base.starts_with("agentkeep-")).then_some(base)
}

/// Install supervisor-side signal handling for the backend in use. Call
/// after [`Backend::launch`]. Ctrl-C reaches the command through the
/// terminal; SIGTERM and SIGHUP are forwarded by [`SandboxHandle::wait`].
pub fn install_supervisor_signals() {
    #[cfg(target_os = "linux")]
    linux::install_supervisor_signals();
    #[cfg(target_os = "macos")]
    macos::install_supervisor_signals();
}

/// Ownership of the terminal for the duration of an approval prompt.
///
/// On Linux the sandbox shares the supervisor's process group and this does
/// nothing. On macOS the sandbox leads its own process group and holds the
/// terminal's foreground; this hands the foreground back to the supervisor
/// so the prompt can be read, and returns it when dropped. A command that
/// reads the terminal meanwhile is stopped by the kernel and continued
/// afterwards, so it cannot swallow the answer.
#[must_use = "the terminal is handed back when the guard is dropped"]
pub struct PromptTerminal {
    #[cfg(target_os = "macos")]
    taken: bool,
}

impl PromptTerminal {
    /// Take the terminal, where that is needed.
    pub fn take() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            taken: macos::take_terminal(),
        }
    }
}

impl Drop for PromptTerminal {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.taken {
            macos::give_terminal_back();
        }
    }
}

/// A chosen backend and the probe that qualified it.
pub type Selected = (Box<dyn Backend>, Probe);
/// Every backend that was considered and why it was rejected.
pub type Rejected = Vec<(&'static str, Probe)>;

/// Pick a backend by name, or the first available one for `auto`.
///
/// Returns the chosen backend and its probe, or a list of every backend's
/// probe when none is usable so the caller can explain exactly why.
pub fn select(name: &str) -> Result<Selected, Rejected> {
    let mut rejected = Vec::new();
    for b in backends() {
        if name != "auto" && b.name() != name {
            continue;
        }
        let probe = b.probe();
        if probe.available() {
            return Ok((b, probe));
        }
        rejected.push((b.name(), probe));
    }
    if rejected.is_empty() && name != "auto" {
        rejected.push((
            "none",
            Probe::unavailable(format!("backend `{name}` is not compiled into this build")),
        ));
    }
    Err(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_detection() {
        assert_eq!(
            invoked_as_shim("/run/agentkeep/bin/git"),
            Some("git".into())
        );
        assert_eq!(invoked_as_shim("git"), Some("git".into()));
        assert_eq!(invoked_as_shim("/usr/local/bin/agentkeep"), None);
        assert_eq!(invoked_as_shim("agentkeep-dev"), None);
        assert_eq!(invoked_as_shim(""), None);
    }

    #[test]
    fn backends_for_this_os() {
        let names: Vec<&str> = backends().iter().map(|b| b.name()).collect();
        if cfg!(target_os = "linux") {
            assert_eq!(names, vec!["linux", "container"]);
        } else if cfg!(target_os = "macos") {
            assert_eq!(names, vec!["macos"]);
        } else {
            assert!(names.is_empty());
        }
    }
}
