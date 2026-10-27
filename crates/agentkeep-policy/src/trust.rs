//! Trust for project policy files (threat model S1).
//!
//! A project's `agentkeep.toml` arrives with the repository, so it is
//! exactly as trustworthy as the repository. Until the user trusts a given
//! file content, only the settings that *tighten* the policy apply; every
//! setting that would loosen it is ignored and reported. Trust is recorded
//! per absolute path and SHA-256 of the content, so any edit to the file
//! makes it untrusted again (the `direnv allow` model).

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentkeep_common::units;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{
    ApprovalSection, CommandsSection, DlpSection, FilesystemSection, LimitsSection, McpSection,
    NetworkSection, PolicyFile, SandboxSection,
};

/// File name of the trust store, next to the global policy.
pub const STORE_FILE_NAME: &str = "trusted.toml";

/// Hex SHA-256 of a policy file's bytes.
pub fn digest(content: &[u8]) -> String {
    let d = Sha256::digest(content);
    d.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Errors reading or writing the trust store.
#[derive(Debug, Error)]
pub enum TrustError {
    /// I/O failure.
    #[error("{path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The store is not valid TOML.
    #[error("{path}: {message}")]
    Format {
        /// File involved.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    #[serde(default)]
    trusted: Vec<Entry>,
}

/// One trusted file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Absolute, canonical path of the policy file.
    pub path: PathBuf,
    /// SHA-256 of the content that was trusted.
    pub sha256: String,
}

/// The user's trust store.
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    entries: Vec<Entry>,
}

/// Canonical form of a policy path for the store; falls back to the path as
/// given when it cannot be resolved.
fn key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

impl TrustStore {
    /// Load `path`, or start empty when it does not exist.
    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let entries = match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str::<StoreFile>(&text)
                    .map_err(|e| TrustError::Format {
                        path: path.to_path_buf(),
                        message: e.message().to_string(),
                    })?
                    .trusted
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(TrustError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Is this exact content of this file trusted?
    pub fn is_trusted(&self, file: &Path, content: &[u8]) -> bool {
        let k = key(file);
        let d = digest(content);
        self.entries.iter().any(|e| e.path == k && e.sha256 == d)
    }

    /// Trust this content of this file, replacing any older entry for it.
    pub fn trust(&mut self, file: &Path, content: &[u8]) {
        let k = key(file);
        self.entries.retain(|e| e.path != k);
        self.entries.push(Entry {
            path: k,
            sha256: digest(content),
        });
    }

    /// Forget a file. Returns whether it was trusted.
    pub fn untrust(&mut self, file: &Path) -> bool {
        let k = key(file);
        let before = self.entries.len();
        self.entries.retain(|e| e.path != k);
        self.entries.len() != before
    }

    /// Write the store (owner-only on Unix), atomically.
    pub fn save(&self) -> Result<(), TrustError> {
        let io = |e| TrustError::Io {
            path: self.path.clone(),
            source: e,
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let text = format!(
            "# agentkeep trusted project policies. Managed by `agentkeep policy trust`.\n# Each entry trusts one exact file content; editing the file revokes it.\n{}",
            toml::to_string(&StoreFile { trusted: self.entries.clone() }).unwrap_or_default()
        );
        let tmp = self.path.with_extension("toml.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        {
            use std::io::Write as _;
            let mut f = options.open(&tmp).map_err(io)?;
            f.write_all(text.as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io)
    }

    /// Where the store lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Keep only the settings of an untrusted project file that tighten the
/// policy, given `current`, the merge of every lower layer. Returns the
/// restricted file and the dotted names of everything that was dropped.
#[allow(clippy::too_many_lines)] // one arm per section keeps the rules auditable
pub fn restrict_untrusted(file: &PolicyFile, current: &PolicyFile) -> (PolicyFile, Vec<String>) {
    let mut kept = PolicyFile {
        schema: file.schema,
        ..PolicyFile::default()
    };
    let mut dropped: Vec<String> = Vec::new();
    let mut drop = |name: &str| dropped.push(name.to_string());

    if let Some(s) = &file.sandbox {
        let mut out = SandboxSection::default();
        if s.backend.is_some() {
            drop("sandbox.backend");
        }
        if s.preset.is_some() {
            drop("sandbox.preset");
        }
        match s.allow_degraded {
            Some(true) => drop("sandbox.allow_degraded"),
            Some(false) => out.allow_degraded = Some(false),
            None => {}
        }
        if out != SandboxSection::default() {
            kept.sandbox = Some(out);
        }
    }

    if let Some(s) = &file.filesystem {
        if s.project.is_some() {
            drop("filesystem.project");
        }
        if !s.read_only.is_empty() {
            drop("filesystem.read_only");
        }
        if !s.read_write.is_empty() {
            drop("filesystem.read_write");
        }
        if !s.hidden.is_empty() {
            kept.filesystem = Some(FilesystemSection {
                hidden: s.hidden.clone(),
                ..Default::default()
            });
        }
    }

    if let Some(s) = &file.env {
        if !s.allow.is_empty() {
            drop("env.allow");
        }
        if !s.pass.is_empty() {
            drop("env.pass");
        }
        if !s.set.is_empty() {
            drop("env.set");
        }
    }

    if let Some(s) = &file.network {
        let mut out = NetworkSection {
            deny: s.deny.clone(),
            ..Default::default()
        };
        for (name, list) in [
            ("network.allow", &s.allow),
            ("network.ask", &s.ask),
            ("network.passthrough", &s.passthrough),
            ("network.trusted_cas", &s.trusted_cas),
        ] {
            if !list.is_empty() {
                drop(name);
            }
        }
        match s.tls_inspect {
            Some(false) => drop("network.tls_inspect"),
            Some(true) => out.tls_inspect = Some(true),
            None => {}
        }
        match s.allow_private {
            Some(true) => drop("network.allow_private"),
            Some(false) => out.allow_private = Some(false),
            None => {}
        }
        if out != NetworkSection::default() {
            kept.network = Some(out);
        }
    }

    if let Some(s) = &file.dlp {
        let mut out = DlpSection {
            block_values: s.block_values.clone(),
            ..Default::default()
        };
        match s.enabled {
            Some(false) => drop("dlp.enabled"),
            Some(true) => out.enabled = Some(true),
            None => {}
        }
        if !s.report_only.is_empty() {
            drop("dlp.report_only");
        }
        if !s.allow_provider_keys_to.is_empty() {
            drop("dlp.allow_provider_keys_to");
        }
        if out != DlpSection::default() {
            kept.dlp = Some(out);
        }
    }

    if let Some(s) = &file.commands {
        if !s.ask.is_empty() || !s.deny.is_empty() {
            kept.commands = Some(CommandsSection {
                ask: s.ask.clone(),
                deny: s.deny.clone(),
            });
        }
    }

    if let Some(s) = &file.mcp {
        let mut out = McpSection {
            deny_tools: s.deny_tools.clone(),
            ..Default::default()
        };
        if !s.allow_tools.is_empty() {
            drop("mcp.allow_tools");
        }
        match s.pin.as_deref() {
            Some("strict") => out.pin = Some("strict".into()),
            Some(_) => drop("mcp.pin"),
            None => {}
        }
        match s.block_injection {
            Some(false) => drop("mcp.block_injection"),
            Some(true) => out.block_injection = Some(true),
            None => {}
        }
        if !s.args.is_empty() {
            drop("mcp.args");
        }
        if out != McpSection::default() {
            kept.mcp = Some(out);
        }
    }

    if let Some(s) = &file.limits {
        let cur = current.limits.clone().unwrap_or_default();
        let mut out = LimitsSection::default();
        let lower = |new: Option<u64>, old: Option<u64>| match (new, old) {
            (Some(n), Some(o)) => n <= o,
            (Some(_), None) => true,
            _ => false,
        };
        if s.cpu_percent.is_some() {
            if lower(s.cpu_percent.map(u64::from), cur.cpu_percent.map(u64::from)) {
                out.cpu_percent = s.cpu_percent;
            } else {
                drop("limits.cpu_percent");
            }
        }
        if s.pids.is_some() {
            if lower(s.pids.map(u64::from), cur.pids.map(u64::from)) {
                out.pids = s.pids;
            } else {
                drop("limits.pids");
            }
        }
        let size = |v: &Option<String>| v.as_deref().and_then(|t| units::parse_size(t).ok());
        if s.memory.is_some() {
            if lower(size(&s.memory), size(&cur.memory)) {
                out.memory.clone_from(&s.memory);
            } else {
                drop("limits.memory");
            }
        }
        let secs = |v: &Option<String>| {
            v.as_deref()
                .and_then(|t| units::parse_duration(t).ok())
                .map(|d| d.as_secs())
        };
        if s.wall_time.is_some() {
            if lower(secs(&s.wall_time), secs(&cur.wall_time)) {
                out.wall_time.clone_from(&s.wall_time);
            } else {
                drop("limits.wall_time");
            }
        }
        if out != LimitsSection::default() {
            kept.limits = Some(out);
        }
    }

    if let Some(s) = &file.approval {
        let cur = current.approval.clone().unwrap_or_default();
        let mut out = ApprovalSection::default();
        if !s.transport.is_empty() {
            drop("approval.transport");
        }
        let secs = |v: &Option<String>| v.as_deref().and_then(|t| units::parse_duration(t).ok());
        if s.timeout.is_some() {
            let current = secs(&cur.timeout).unwrap_or(Duration::from_mins(1));
            if secs(&s.timeout).is_some_and(|t| t <= current) {
                out.timeout.clone_from(&s.timeout);
            } else {
                drop("approval.timeout");
            }
        }
        if out != ApprovalSection::default() {
            kept.approval = Some(out);
        }
    }

    if file.audit.is_some() {
        drop("audit");
    }
    if file.r#override.is_some() {
        drop("override");
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;

    fn defaults() -> PolicyFile {
        parse_str(crate::defaults::DEFAULT_POLICY, "d").unwrap()
    }

    #[test]
    fn loosening_settings_are_dropped_and_tightening_kept() {
        let f = parse_str(
            r#"schema = 1
[sandbox]
backend = "container"
allow_degraded = true
[filesystem]
project = ".."
read_only = ["~"]
read_write = ["~/.config"]
hidden = ["$PROJECT/.env"]
[env]
pass = ["AWS_SECRET_ACCESS_KEY"]
[network]
allow = ["evil.example"]
deny = ["*.pastebin.com"]
tls_inspect = false
allow_private = true
[dlp]
enabled = false
block_values = ["fake-block-value"]
[commands]
deny = ["make deploy*"]
[limits]
memory = "64G"
pids = 64
[approval]
transport = ["socket"]
timeout = "5m"
[audit]
redact = false
[override]
acknowledge = true
unhide = ["~/.ssh"]
"#,
            "p",
        )
        .unwrap();
        let (kept, dropped) = restrict_untrusted(&f, &defaults());
        for name in [
            "sandbox.backend",
            "sandbox.allow_degraded",
            "filesystem.project",
            "filesystem.read_only",
            "filesystem.read_write",
            "env.pass",
            "network.allow",
            "network.tls_inspect",
            "network.allow_private",
            "dlp.enabled",
            "limits.memory",
            "approval.transport",
            "approval.timeout",
            "audit",
            "override",
        ] {
            assert!(
                dropped.iter().any(|d| d == name),
                "{name} not dropped: {dropped:?}"
            );
        }
        assert_eq!(kept.filesystem.unwrap().hidden, vec!["$PROJECT/.env"]);
        assert_eq!(kept.network.as_ref().unwrap().deny, vec!["*.pastebin.com"]);
        assert!(kept.network.as_ref().unwrap().allow.is_empty());
        assert_eq!(kept.dlp.unwrap().block_values, vec!["fake-block-value"]);
        assert_eq!(kept.commands.unwrap().deny, vec!["make deploy*"]);
        let limits = kept.limits.unwrap();
        assert_eq!(limits.pids, Some(64), "lower pid limit is a tightening");
        assert_eq!(limits.memory, None, "higher memory limit is a loosening");
        assert!(kept.r#override.is_none() && kept.audit.is_none() && kept.env.is_none());
    }

    #[test]
    fn a_tightening_only_file_loses_nothing() {
        let f = parse_str(
            "schema = 1\n[network]\ndeny = [\"x.example\"]\n[limits]\nwall_time = \"10m\"\n",
            "p",
        )
        .unwrap();
        let (kept, dropped) = restrict_untrusted(&f, &defaults());
        assert!(dropped.is_empty(), "{dropped:?}");
        assert_eq!(kept.limits.unwrap().wall_time.as_deref(), Some("10m"));
    }

    #[test]
    fn store_roundtrip_and_content_binding() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("agentkeep.toml");
        std::fs::write(&policy, "schema = 1\n").unwrap();
        let store_path = dir.path().join("cfg/trusted.toml");
        let mut store = TrustStore::load(&store_path).unwrap();
        assert!(!store.is_trusted(&policy, b"schema = 1\n"));
        store.trust(&policy, b"schema = 1\n");
        store.save().unwrap();
        let store = TrustStore::load(&store_path).unwrap();
        assert!(store.is_trusted(&policy, b"schema = 1\n"));
        assert!(
            !store.is_trusted(&policy, b"schema = 1\n[network]\nallow=[\"x.example\"]\n"),
            "edits revoke trust"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&store_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
