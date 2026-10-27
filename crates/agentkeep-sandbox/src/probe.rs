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
    /// Memory and pid limits via cgroup v2. For a container runtime: the
    /// runtime enforces `--memory` and `--pids-limit` through the
    /// container's cgroup (v2, or v1 on legacy hosts).
    pub cgroup_v2: bool,
    /// Memory and pid limits via rlimits (approximate).
    pub rlimits: bool,
    /// `no_new_privs` and an unprivileged uid inside.
    pub no_new_privs: bool,
    /// A macOS Seatbelt profile confines the process tree.
    #[serde(default)]
    pub seatbelt: bool,
    /// Name of the container runtime in use (`podman`, `docker`), if any.
    #[serde(default)]
    pub container_runtime: Option<String>,
}

impl Capabilities {
    /// Controls this backend claims, by stable name. The escape suite gates
    /// each test on these, so a backend is only ever tested against what it
    /// says it enforces, and everything else is reported as not applicable
    /// rather than silently passed.
    ///
    /// - `fs_absent`: paths outside the policy do not exist (mount view).
    /// - `fs_denied`: paths outside the policy cannot be read or written.
    /// - `hardlink_safe`: hardlinks cannot expose files outside the policy.
    /// - `pid_isolation`: host processes are invisible.
    /// - `ptrace_denied`: debugging and cross-process memory access fail.
    /// - `no_mount`: mounts and new namespaces are refused.
    /// - `net_isolation`: no network path except the proxy.
    /// - `net_namespace`: only a loopback interface exists.
    /// - `seccomp`, `landlock`: those kernel filters are active.
    /// - `no_caps`: no Linux capabilities and `no_new_privs` set.
    /// - `rlimits`: memory (`RLIMIT_AS` or cgroup) and pids limits that
    ///   count only the sandbox's own processes.
    /// - `cgroup_limits`: memory and pid limits live in a cgroup that is
    ///   visible (read-only) inside the sandbox, so they can be checked from
    ///   there. Container runtimes only: the Linux backend's cgroup is not
    ///   mounted inside its sandbox.
    /// - `no_core_dumps`: `RLIMIT_CORE` is 0.
    /// - `nproc_per_user`: `RLIMIT_NPROC` is set, but counts every process
    ///   of the user (macOS), so it is an approximate fork-bomb brake.
    ///
    /// Seatbelt claims only `fs_denied`, `net_isolation`, `no_core_dumps`
    /// and `nproc_per_user`. It does not claim `ptrace_denied`: the profile
    /// does not filter `ptrace(2)` and the suite's probe for it is a Linux
    /// system call sequence.
    pub fn controls(&self) -> Vec<&'static str> {
        let mut c = Vec::new();
        if self.mount_namespace {
            c.extend(["fs_absent", "fs_denied", "hardlink_safe"]);
        } else if self.seatbelt {
            c.push("fs_denied");
        }
        if self.pid_namespace {
            c.push("pid_isolation");
        }
        if self.seccomp {
            c.push("ptrace_denied");
        }
        if self.seccomp && self.mount_namespace {
            c.push("no_mount");
        }
        if self.net_namespace || self.seatbelt {
            c.push("net_isolation");
        }
        if self.net_namespace {
            c.push("net_namespace");
        }
        if self.seccomp {
            c.push("seccomp");
        }
        if self.landlock_abi > 0 {
            c.push("landlock");
        }
        if self.no_new_privs && cfg!(target_os = "linux") {
            c.push("no_caps");
        }
        if self.rlimits {
            c.push("no_core_dumps");
            if self.seatbelt {
                c.push("nproc_per_user");
            } else {
                c.push("rlimits");
            }
        }
        if self.cgroup_v2 && self.container_runtime.is_some() {
            c.push("cgroup_limits");
        }
        c
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_controls() {
        let caps = Capabilities {
            mount_namespace: true,
            pid_namespace: true,
            net_namespace: true,
            landlock_abi: 4,
            seccomp: true,
            cgroup_v2: false,
            rlimits: true,
            no_new_privs: true,
            seatbelt: false,
            container_runtime: None,
        };
        let c = caps.controls();
        for want in [
            "fs_absent",
            "fs_denied",
            "hardlink_safe",
            "pid_isolation",
            "ptrace_denied",
            "no_mount",
            "net_isolation",
            "net_namespace",
            "seccomp",
            "landlock",
            "rlimits",
            "no_core_dumps",
        ] {
            assert!(c.contains(&want), "{want} missing from {c:?}");
        }
        assert!(!c.contains(&"nproc_per_user"));
    }

    #[test]
    fn seatbelt_claims_only_what_its_profile_enforces() {
        let caps = Capabilities {
            seatbelt: true,
            rlimits: true,
            ..Capabilities::default()
        };
        assert_eq!(
            caps.controls(),
            vec![
                "fs_denied",
                "net_isolation",
                "no_core_dumps",
                "nproc_per_user"
            ]
        );
    }

    fn namespaces() -> Capabilities {
        Capabilities {
            mount_namespace: true,
            pid_namespace: true,
            net_namespace: true,
            landlock_abi: 5,
            seccomp: true,
            cgroup_v2: true,
            rlimits: true,
            no_new_privs: true,
            seatbelt: false,
            container_runtime: None,
        }
    }

    #[test]
    fn cgroup_limits_are_claimed_only_by_container_runtimes() {
        let linux = namespaces();
        assert!(!linux.controls().contains(&"cgroup_limits"));
        let container = Capabilities {
            container_runtime: Some("docker".into()),
            ..namespaces()
        };
        let c = container.controls();
        assert!(c.contains(&"cgroup_limits"));
        // Everything the namespaces backend claims, the container claims.
        for control in linux.controls() {
            assert!(c.contains(&control), "{control}");
        }
        let no_limits = Capabilities {
            cgroup_v2: false,
            ..container
        };
        assert!(!no_limits.controls().contains(&"cgroup_limits"));
    }
}
