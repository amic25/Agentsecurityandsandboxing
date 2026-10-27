//! Sandbox backends.
//!
//! A [`Backend`] turns a backend-agnostic [`LaunchPlan`] into a confined
//! process tree. Each backend reports what it can enforce through
//! [`Capabilities`]; the caller compares that with the policy and refuses to
//! run (or runs with recorded degradations) when they disagree.
//!
//! Linux hosts have two backends: `linux` (namespaces, preferred) and
//! `container` (Podman or Docker through their CLI). On other operating
//! systems no backend is compiled in yet and `agentkeep run` says so.
//!
//! `unsafe` is confined to `linux::sys`; every block carries a `SAFETY`
//! comment. Everything else in this crate forbids it.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod plan;
pub mod probe;

#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod linux;

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
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
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
