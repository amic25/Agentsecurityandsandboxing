//! The fully merged, validated policy with concrete types.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentkeep_common::{paths, units};
use thiserror::Error;

use crate::schema::PolicyFile;

/// Which sandbox backend the policy asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Pick the first available backend for this OS.
    Auto,
    /// Linux namespaces, Landlock and seccomp.
    Linux,
    /// macOS Seatbelt.
    Macos,
    /// Podman or Docker.
    Container,
    /// WSL2 re-execution on Windows.
    Wsl,
}

impl BackendKind {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "auto" => Self::Auto,
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "container" => Self::Container,
            "wsl" => Self::Wsl,
            _ => return None,
        })
    }

    /// Canonical name as written in a policy file.
    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Container => "container",
            Self::Wsl => "wsl",
        }
    }
}

/// How the MCP gateway treats a changed tool definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Refuse to start.
    Strict,
    /// Log and prompt.
    Warn,
    /// Ignore.
    Off,
}

/// Approval transports, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Prompt on the controlling terminal.
    Tty,
    /// Prompt over the approval Unix socket.
    Socket,
}

/// Resource limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// CPU quota in percent of one core.
    pub cpu_percent: Option<u32>,
    /// Memory limit in bytes.
    pub memory: Option<u64>,
    /// Maximum processes.
    pub pids: Option<u32>,
    /// Session wall-clock limit.
    pub wall_time: Option<Duration>,
}

/// MCP gateway rules.
#[derive(Debug, Clone, PartialEq)]
pub struct McpPolicy {
    /// Allowed `server:tool` globs.
    pub allow_tools: Vec<String>,
    /// Denied `server:tool` globs.
    pub deny_tools: Vec<String>,
    /// Rug-pull handling.
    pub pin: PinMode,
    /// Block suspected injection in results.
    pub block_injection: bool,
    /// Per-server argument rules (validated by the gateway).
    pub args: BTreeMap<String, toml::Table>,
}

/// The resolved policy. All paths are absolute and normalised.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // each switch is an independent policy knob
pub struct Policy {
    /// Requested backend.
    pub backend: BackendKind,
    /// Run with a backend that cannot enforce everything.
    pub allow_degraded: bool,
    /// Preset name, if fixed by the policy.
    pub preset: Option<String>,
    /// Read-write project root.
    pub project: PathBuf,
    /// Read-only paths.
    pub read_only: Vec<PathBuf>,
    /// Read-write paths besides the project.
    pub read_write: Vec<PathBuf>,
    /// Hidden paths.
    pub hidden: Vec<PathBuf>,
    /// Environment names or `PREFIX_*` globs passed through.
    pub env_allow: Vec<String>,
    /// Secrets passed through.
    pub env_pass: Vec<String>,
    /// Fixed environment values.
    pub env_set: BTreeMap<String, String>,
    /// Allowed hosts.
    pub net_allow: Vec<String>,
    /// Ask-on-first-contact hosts.
    pub net_ask: Vec<String>,
    /// Denied hosts.
    pub net_deny: Vec<String>,
    /// TLS inspection on.
    pub tls_inspect: bool,
    /// Hosts exempt from inspection.
    pub passthrough: Vec<String>,
    /// Private ranges allowed.
    pub allow_private: bool,
    /// DLP on.
    pub dlp_enabled: bool,
    /// Extra literal values to block.
    pub dlp_block_values: Vec<String>,
    /// Secret name to allowed domains.
    pub dlp_provider_domains: BTreeMap<String, Vec<String>>,
    /// Command globs that ask.
    pub cmd_ask: Vec<String>,
    /// Command globs that deny.
    pub cmd_deny: Vec<String>,
    /// MCP rules.
    pub mcp: McpPolicy,
    /// Resource limits.
    pub limits: Limits,
    /// Approval transports in order.
    pub approval_transports: Vec<Transport>,
    /// Approval timeout.
    pub approval_timeout: Duration,
    /// Audit directory.
    pub audit_dir: PathBuf,
    /// Redact secrets in the audit log.
    pub audit_redact: bool,
}

/// Validation errors found while resolving a merged policy.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A field holds a value outside its allowed set.
    #[error("{field}: {message}")]
    Invalid {
        /// Dotted field name, e.g. `sandbox.backend`.
        field: String,
        /// What is wrong.
        message: String,
    },
}

impl ResolveError {
    fn invalid(field: &str, message: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.to_string(),
            message: message.into(),
        }
    }
}

/// Values needed to turn relative and `~` paths into absolute ones.
#[derive(Debug, Clone)]
pub struct Context {
    /// The user's home directory.
    pub home: PathBuf,
    /// Base directory for a relative `filesystem.project`.
    pub base_dir: PathBuf,
}

impl Policy {
    /// Validate and resolve a merged [`PolicyFile`].
    #[allow(clippy::too_many_lines)]
    pub fn resolve(file: &PolicyFile, ctx: &Context) -> Result<Self, ResolveError> {
        let sandbox = file.sandbox.clone().unwrap_or_default();
        let backend = match sandbox.backend.as_deref() {
            None => BackendKind::Auto,
            Some(s) => BackendKind::parse(s).ok_or_else(|| {
                ResolveError::invalid(
                    "sandbox.backend",
                    format!("`{s}` is not one of auto, linux, macos, container, wsl"),
                )
            })?,
        };

        let fs = file.filesystem.clone().unwrap_or_default();
        let project_raw = fs.project.as_deref().unwrap_or(".");
        let project = {
            let p = paths::expand(project_raw, &ctx.home, &ctx.base_dir);
            if p.is_absolute() {
                p
            } else {
                paths::normalize(&ctx.base_dir.join(p))
            }
        };
        if !project.is_absolute() {
            return Err(ResolveError::invalid(
                "filesystem.project",
                "must resolve to an absolute path",
            ));
        }
        let expand_all = |field: &str, items: &[String]| -> Result<Vec<PathBuf>, ResolveError> {
            let mut out = Vec::with_capacity(items.len());
            for raw in items {
                if raw.trim().is_empty() {
                    return Err(ResolveError::invalid(field, "empty path"));
                }
                let p = paths::expand(raw, &ctx.home, &project);
                if !p.is_absolute() {
                    return Err(ResolveError::invalid(
                        field,
                        format!("`{raw}` must be absolute or start with ~ or $PROJECT"),
                    ));
                }
                if !out.contains(&p) {
                    out.push(p);
                }
            }
            Ok(out)
        };
        let read_only = expand_all("filesystem.read_only", &fs.read_only)?;
        let read_write = expand_all("filesystem.read_write", &fs.read_write)?;
        let hidden = expand_all("filesystem.hidden", &fs.hidden)?;
        for p in &read_write {
            if p == Path::new("/") || *p == ctx.home {
                return Err(ResolveError::invalid(
                    "filesystem.read_write",
                    format!(
                        "refusing to make `{}` writable; list specific directories",
                        p.display()
                    ),
                ));
            }
        }

        let env = file.env.clone().unwrap_or_default();
        for name in env
            .allow
            .iter()
            .chain(env.pass.iter())
            .chain(env.set.keys())
        {
            validate_env_name(name)?;
        }

        let net = file.network.clone().unwrap_or_default();
        for (field, list) in [
            ("network.allow", &net.allow),
            ("network.ask", &net.ask),
            ("network.deny", &net.deny),
            ("network.passthrough", &net.passthrough),
        ] {
            for host in list {
                validate_host_pattern(field, host)?;
            }
        }

        let dlp = file.dlp.clone().unwrap_or_default();
        for (name, domains) in &dlp.allow_provider_keys_to {
            validate_env_name(name)?;
            for d in domains {
                validate_host_pattern("dlp.allow_provider_keys_to", d)?;
            }
        }

        let cmds = file.commands.clone().unwrap_or_default();
        for (field, list) in [("commands.ask", &cmds.ask), ("commands.deny", &cmds.deny)] {
            for pat in list {
                if pat.trim().is_empty() {
                    return Err(ResolveError::invalid(field, "empty pattern"));
                }
                globset::GlobBuilder::new(pat)
                    .literal_separator(false)
                    .build()
                    .map_err(|e| ResolveError::invalid(field, format!("`{pat}`: {e}")))?;
            }
        }

        let mcp_raw = file.mcp.clone().unwrap_or_default();
        let pin = match mcp_raw.pin.as_deref() {
            None | Some("strict") => PinMode::Strict,
            Some("warn") => PinMode::Warn,
            Some("off") => PinMode::Off,
            Some(other) => {
                return Err(ResolveError::invalid(
                    "mcp.pin",
                    format!("`{other}` is not one of strict, warn, off"),
                ));
            }
        };

        let lim = file.limits.clone().unwrap_or_default();
        let memory = lim
            .memory
            .as_deref()
            .map(|s| {
                units::parse_size(s)
                    .map_err(|e| ResolveError::invalid("limits.memory", e.to_string()))
            })
            .transpose()?;
        let wall_time = lim
            .wall_time
            .as_deref()
            .map(|s| {
                units::parse_duration(s)
                    .map_err(|e| ResolveError::invalid("limits.wall_time", e.to_string()))
            })
            .transpose()?;
        if lim.pids == Some(0) {
            return Err(ResolveError::invalid("limits.pids", "must be at least 1"));
        }
        if lim.cpu_percent == Some(0) {
            return Err(ResolveError::invalid(
                "limits.cpu_percent",
                "must be at least 1",
            ));
        }

        let appr = file.approval.clone().unwrap_or_default();
        let mut approval_transports = Vec::new();
        for t in &appr.transport {
            let t = match t.as_str() {
                "tty" => Transport::Tty,
                "socket" => Transport::Socket,
                other => {
                    return Err(ResolveError::invalid(
                        "approval.transport",
                        format!("`{other}` is not one of tty, socket"),
                    ));
                }
            };
            if !approval_transports.contains(&t) {
                approval_transports.push(t);
            }
        }
        let approval_timeout = match appr.timeout.as_deref() {
            None => Duration::from_mins(1),
            Some(s) => units::parse_duration(s)
                .map_err(|e| ResolveError::invalid("approval.timeout", e.to_string()))?,
        };

        let audit = file.audit.clone().unwrap_or_default();
        let audit_dir = paths::expand(
            audit
                .dir
                .as_deref()
                .unwrap_or("~/.local/share/agentkeep/sessions"),
            &ctx.home,
            &project,
        );

        Ok(Self {
            backend,
            allow_degraded: sandbox.allow_degraded.unwrap_or(false),
            preset: sandbox.preset,
            project,
            read_only,
            read_write,
            hidden,
            env_allow: env.allow,
            env_pass: env.pass,
            env_set: env.set,
            net_allow: net.allow,
            net_ask: net.ask,
            net_deny: net.deny,
            tls_inspect: net.tls_inspect.unwrap_or(true),
            passthrough: net.passthrough,
            allow_private: net.allow_private.unwrap_or(false),
            dlp_enabled: dlp.enabled.unwrap_or(true),
            dlp_block_values: dlp.block_values,
            dlp_provider_domains: dlp.allow_provider_keys_to,
            cmd_ask: cmds.ask,
            cmd_deny: cmds.deny,
            mcp: McpPolicy {
                allow_tools: mcp_raw.allow_tools,
                deny_tools: mcp_raw.deny_tools,
                pin,
                block_injection: mcp_raw.block_injection.unwrap_or(false),
                args: mcp_raw.args,
            },
            limits: Limits {
                cpu_percent: lim.cpu_percent,
                memory,
                pids: lim.pids,
                wall_time,
            },
            approval_transports,
            approval_timeout,
            audit_dir,
            audit_redact: audit.redact.unwrap_or(true),
        })
    }
}

fn validate_env_name(name: &str) -> Result<(), ResolveError> {
    let ok = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*');
    if ok {
        Ok(())
    } else {
        Err(ResolveError::invalid(
            "env",
            format!("`{name}` is not a valid variable name"),
        ))
    }
}

fn validate_host_pattern(field: &str, host: &str) -> Result<(), ResolveError> {
    let h = host.strip_prefix("*.").unwrap_or(host);
    let (h, port) = match h.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (name, Some(port))
        }
        _ => (h, None),
    };
    if let Some(p) = port {
        if p.parse::<u16>().is_err() {
            return Err(ResolveError::invalid(
                field,
                format!("`{host}`: port out of range"),
            ));
        }
    }
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if h.is_empty() || h.len() > 253 || !h.split('.').all(valid_label) {
        return Err(ResolveError::invalid(
            field,
            format!("`{host}` is not a hostname or `*.suffix` pattern"),
        ));
    }
    if host == "*" || host.starts_with("*.") && h.split('.').count() < 2 {
        return Err(ResolveError::invalid(
            field,
            format!("`{host}` is too broad; name at least a second-level domain"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;

    fn ctx() -> Context {
        Context {
            home: PathBuf::from("/home/u"),
            base_dir: PathBuf::from("/home/u/proj"),
        }
    }

    fn resolve(text: &str) -> Result<Policy, ResolveError> {
        let f = parse_str(text, "t").unwrap();
        Policy::resolve(&f, &ctx())
    }

    #[test]
    fn resolves_defaults() {
        let p = resolve(crate::defaults::DEFAULT_POLICY).unwrap();
        assert_eq!(p.project, PathBuf::from("/home/u/proj"));
        assert!(p.hidden.contains(&PathBuf::from("/home/u/.ssh")));
        assert_eq!(p.limits.memory, Some(8 << 30));
        assert_eq!(
            p.approval_transports,
            vec![Transport::Tty, Transport::Socket]
        );
        assert!(p.tls_inspect && p.dlp_enabled && p.audit_redact);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(resolve("schema=1\n[sandbox]\nbackend='vm'\n").is_err());
        assert!(resolve("schema=1\n[limits]\nmemory='lots'\n").is_err());
        assert!(resolve("schema=1\n[network]\nallow=['*']\n").is_err());
        assert!(resolve("schema=1\n[network]\nallow=['*.com']\n").is_err());
        assert!(resolve("schema=1\n[network]\nallow=['bad host']\n").is_err());
        assert!(resolve("schema=1\n[commands]\ndeny=['[']\n").is_err());
        assert!(resolve("schema=1\n[filesystem]\nread_write=['~']\n").is_err());
        assert!(resolve("schema=1\n[filesystem]\nread_write=['relative']\n").is_err());
        assert!(resolve("schema=1\n[env]\nallow=['1BAD']\n").is_err());
        assert!(resolve("schema=1\n[mcp]\npin='maybe'\n").is_err());
        assert!(resolve("schema=1\n[approval]\ntransport=['carrier-pigeon']\n").is_err());
    }

    #[test]
    fn accepts_good_hosts() {
        let p = resolve(
            "schema=1\n[network]\nallow=['api.anthropic.com','*.npmjs.org','localhost:8080','registry.example.co.uk']\n",
        )
        .unwrap();
        assert_eq!(p.net_allow.len(), 4);
    }

    #[test]
    fn expands_project_variable() {
        let p = resolve("schema=1\n[filesystem]\nhidden=['$PROJECT/.env']\n").unwrap();
        assert_eq!(p.hidden, vec![PathBuf::from("/home/u/proj/.env")]);
    }
}
