//! The on-disk shape of `agentkeep.toml`.
//!
//! Every field is optional so that a file can state only what it changes.
//! Unknown keys are rejected: a typo in a security rule must fail loudly
//! rather than silently leave the default in place.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A parsed but not yet merged policy file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Schema version. Required in every file; must equal [`crate::SCHEMA_VERSION`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<u32>,
    /// Sandbox selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxSection>,
    /// Filesystem rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemSection>,
    /// Environment variable rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvSection>,
    /// Network rules (enforced by the egress proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSection>,
    /// Data-loss-protection rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp: Option<DlpSection>,
    /// Command rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<CommandsSection>,
    /// MCP gateway rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSection>,
    /// Resource limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsSection>,
    /// Approval prompt settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSection>,
    /// Audit log settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSection>,
    /// Explicit loosening of lower-priority rules. Project file only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#override: Option<OverrideSection>,
}

/// `[sandbox]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSection {
    /// `auto`, `linux`, `macos`, `container` or `wsl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Run even if the backend cannot enforce every rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_degraded: Option<bool>,
    /// Preset name; auto-detected from the command when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

/// `[filesystem]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSection {
    /// The read-write project root. Relative paths resolve against the policy
    /// file's directory (or the current directory for CLI overrides).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Extra paths visible read-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    /// Extra paths visible read-write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<String>,
    /// Paths that must not exist inside the sandbox, even under a visible tree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
}

/// `[env]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSection {
    /// Variables passed through unchanged (exact names or `PREFIX_*` globs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Secrets passed through deliberately. Bound to provider domains by DLP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass: Vec<String>,
    /// Variables set to fixed values inside the sandbox.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
}

/// `[network]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// Hosts the agent may reach. `*.suffix` matches subdomains only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Hosts that prompt on first contact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    /// Hosts that are always refused. Deny beats ask beats allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Decrypt TLS for DLP scanning (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_inspect: Option<bool>,
    /// Allowed hosts exempt from TLS inspection (pinned clients). No DLP there.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough: Vec<String>,
    /// Permit connections to private and link-local address ranges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private: Option<bool>,
    /// Extra PEM bundles trusted when the proxy connects to origins
    /// (corporate CAs, test fixtures).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_cas: Vec<String>,
}

/// `[dlp]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpSection {
    /// Master switch (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Literal values to block anywhere in outbound traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_values: Vec<String>,
    /// Which domains each passed secret may travel to.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allow_provider_keys_to: BTreeMap<String, Vec<String>>,
    /// Detector ids that log instead of blocking (see `docs/policy.md`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub report_only: Vec<String>,
}

/// `[commands]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsSection {
    /// Command globs that prompt before running.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    /// Command globs that are refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// `[mcp]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSection {
    /// `server:tool` globs the agent may call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_tools: Vec<String>,
    /// `server:tool` globs that are refused and hidden.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_tools: Vec<String>,
    /// `strict`, `warn` or `off`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Replace tool results that look like injection with an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_injection: Option<bool>,
    /// Per-server argument rules, keyed by server name. Free-form until the
    /// gateway lands; validated there.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, toml::Table>,
}

/// `[limits]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// CPU quota in percent of one core (200 = two cores). cgroup backends only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<u32>,
    /// Memory limit, e.g. `4G`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// Maximum number of processes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u32>,
    /// Wall-clock limit for the whole session, e.g. `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<String>,
}

/// `[approval]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSection {
    /// Ordered transports: `tty`, `socket`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport: Vec<String>,
    /// How long to wait for an answer before denying, e.g. `60s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// `[audit]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Directory that holds one subdirectory per session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Redact values that look like secrets before logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact: Option<bool>,
}

/// `[override]`: the only way to loosen a lower-priority rule. Every entry
/// is reported as a warning at startup and written to the audit log.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideSection {
    /// Must be `true` for the section to take effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledge: Option<bool>,
    /// Hidden paths to make visible again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unhide: Vec<String>,
    /// Denied domains to stop denying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undeny_domains: Vec<String>,
    /// Denied commands to stop denying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undeny_commands: Vec<String>,
}
