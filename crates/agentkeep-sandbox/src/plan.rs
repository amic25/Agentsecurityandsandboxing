//! The backend-agnostic description of a sandbox.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// What a mount looks like inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountMode {
    /// Bind read-only (`nosuid`, `nodev`).
    ReadOnly,
    /// Bind read-write (`nosuid`, `nodev`).
    ReadWrite,
    /// Replace with an empty, read-only placeholder so the path exists but
    /// holds nothing. Used for hidden paths under a visible tree.
    Hidden,
    /// A fresh, private tmpfs.
    Tmpfs,
}

/// One filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    /// Host path (ignored for `Tmpfs` and `Hidden`).
    pub source: PathBuf,
    /// Path inside the sandbox.
    pub target: PathBuf,
    /// Mode.
    pub mode: MountMode,
    /// Size limit in bytes for tmpfs mounts.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Resource limits the backend should apply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// CPU quota in percent of one core.
    pub cpu_percent: Option<u32>,
    /// Memory limit in bytes.
    pub memory: Option<u64>,
    /// Maximum processes.
    pub pids: Option<u32>,
    /// Wall-clock limit in seconds (enforced by the supervisor).
    pub wall_time_secs: Option<u64>,
}

/// Command shims: symlinks to the agentkeep binary placed first on `PATH`
/// so that sensitive commands consult the policy before running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimConfig {
    /// Directory inside the sandbox that holds the shims.
    pub dir: PathBuf,
    /// Command names to shim.
    pub commands: Vec<String>,
    /// Approval socket path, as seen inside the sandbox.
    pub socket: PathBuf,
}

/// How the sandbox reaches the egress proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPlan {
    /// Host path of the proxy's Unix socket.
    pub host_socket: PathBuf,
    /// Where it appears inside the sandbox.
    pub sandbox_socket: PathBuf,
    /// Loopback TCP port the in-sandbox relay listens on.
    pub port: u16,
    /// Host path of the CA bundle (system roots plus the session CA).
    pub ca_bundle_host: PathBuf,
    /// Where the bundle appears inside the sandbox.
    pub ca_bundle_sandbox: PathBuf,
}

/// Everything a backend needs to start a sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
    /// Session id, used in hostnames and logs.
    pub session_id: String,
    /// Mounts, applied in order after sorting by depth.
    pub mounts: Vec<Mount>,
    /// The read-write project root (also mounted; listed for clarity).
    pub project: PathBuf,
    /// Home directory path inside the sandbox (a private tmpfs).
    pub home: PathBuf,
    /// Exact environment for the command.
    pub env: BTreeMap<String, String>,
    /// Working directory inside the sandbox.
    pub cwd: PathBuf,
    /// Command and arguments.
    pub command: Vec<String>,
    /// Limits.
    pub limits: Limits,
    /// Hostname inside the sandbox.
    pub hostname: String,
    /// Host path of the agentkeep binary, for shims.
    pub self_exe: PathBuf,
    /// An empty host directory the backend may mount its private root on.
    /// Created by the supervisor, removed when the session ends.
    pub root_base: PathBuf,
    /// User name to publish in the sandbox's `/etc/passwd` for `inner_uid`.
    pub user_name: String,
    /// Host path of the approval socket, bind-mounted to `shim.socket`.
    pub approval_socket: Option<PathBuf>,
    /// Shim configuration.
    pub shim: Option<ShimConfig>,
    /// Egress proxy wiring. `None` means no network at all.
    pub proxy: Option<ProxyPlan>,
    /// Host paths that must never be reachable from inside, such as the
    /// approver socket (threat model B3). A mount-namespace backend never
    /// mounts them; a backend that shares the host's file tree (macOS)
    /// denies them explicitly and refuses to start if an allowed path would
    /// contain one.
    #[serde(default)]
    pub host_only: Vec<PathBuf>,
    /// Apply a Landlock ruleset in addition to mounts when available.
    pub landlock: bool,
    /// Apply the seccomp deny-list.
    pub seccomp: bool,
    /// UID and GID the command runs as inside the sandbox.
    pub inner_uid: u32,
    /// See `inner_uid`.
    pub inner_gid: u32,
}

impl LaunchPlan {
    /// Serialise for transfer to the init process.
    pub fn to_json(&self) -> Result<String, crate::Error> {
        serde_json::to_string(self).map_err(|e| crate::Error::Plan(e.to_string()))
    }

    /// Parse a plan written by [`LaunchPlan::to_json`].
    pub fn from_json(text: &str) -> Result<Self, crate::Error> {
        serde_json::from_str(text).map_err(|e| crate::Error::Plan(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_roundtrips() {
        let plan = LaunchPlan {
            session_id: "s".into(),
            mounts: vec![Mount {
                source: "/usr".into(),
                target: "/usr".into(),
                mode: MountMode::ReadOnly,
                size: None,
            }],
            project: "/p".into(),
            home: "/home/u".into(),
            env: BTreeMap::from([("HOME".into(), "/home/u".into())]),
            cwd: "/p".into(),
            command: vec!["true".into()],
            limits: Limits::default(),
            hostname: "agentkeep".into(),
            self_exe: "/bin/agentkeep".into(),
            root_base: "/tmp/agentkeep.x".into(),
            user_name: "agent".into(),
            approval_socket: None,
            shim: None,
            proxy: None,
            host_only: vec!["/tmp/agentkeep.x/approve.sock".into()],
            landlock: true,
            seccomp: true,
            inner_uid: 1000,
            inner_gid: 1000,
        };
        let back = LaunchPlan::from_json(&plan.to_json().unwrap()).unwrap();
        assert_eq!(plan, back);
    }
}
