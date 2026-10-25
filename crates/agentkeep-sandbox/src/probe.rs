//! Backend availability and capability reporting.

use serde::{Deserialize, Serialize};

/// A protection the backend cannot provide in full on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Degradation {
    /// Which control, in threat-model terms (e.g. `landlock`, `cgroup`).
    pub control: String,
    /// What is used instead, or that nothing is.
    pub fallback: String,
    /// Why.
    pub reason: String,
}

/// What a backend can enforce here. Every field is a fact about this host,
/// discovered by probing, never assumed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // one flag per independent control
pub struct Capabilities {
    /// Private mount namespace: paths outside the policy do not exist.
    pub mount_namespace: bool,
    /// Private PID namespace and fresh `/proc`.
    pub pid_namespace: bool,
    /// Private network namespace with no interfaces but loopback.
    pub net_namespace: bool,
    /// Landlock filesystem rules as a second layer.
    pub landlock_abi: u32,
    /// seccomp syscall deny-list.
    pub seccomp: bool,
    /// Memory and pid limits via cgroup v2.
    pub cgroup_v2: bool,
    /// Memory and pid limits via rlimits (approximate).
    pub rlimits: bool,
    /// `no_new_privs` and an unprivileged uid inside.
    pub no_new_privs: bool,
}

/// Result of probing a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Probe {
    /// Usable; may carry degradations.
    Available {
        /// What it can do.
        capabilities: Capabilities,
        /// What it cannot do in full.
        degradations: Vec<Degradation>,
    },
    /// Not usable here.
    Unavailable {
        /// Why, with a fix hint where one exists.
        reason: String,
    },
}

impl Probe {
    /// Shorthand constructor.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    /// Is the backend usable?
    pub fn available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Capabilities, if available.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        match self {
            Self::Available { capabilities, .. } => Some(capabilities),
            Self::Unavailable { .. } => None,
        }
    }

    /// Degradations, if available.
    pub fn degradations(&self) -> &[Degradation] {
        match self {
            Self::Available { degradations, .. } => degradations,
            Self::Unavailable { .. } => &[],
        }
    }
}
