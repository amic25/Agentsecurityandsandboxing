//! Command-line surface. Kept in one place so `--help` output is reviewable
//! as a whole and so docs can be generated from it later.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Run any agent with one command. It can only touch what you allow, and you
/// can see everything it did.
#[derive(Debug, Parser)]
#[command(
    name = "agentkeep",
    version,
    about,
    long_about = None,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Path to a policy file. Defaults to ./agentkeep.toml, searched upward to
    /// the git root, merged over the global config and built-in defaults.
    #[arg(long, global = true, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Increase log verbosity (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Never prompt. Any action that would ask is denied.
    #[arg(long, global = true)]
    pub no_ask: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Global options, passed to every command.
#[derive(Debug, Clone)]
pub struct Globals {
    /// Explicit policy file.
    pub policy: Option<PathBuf>,
    /// Verbosity.
    pub verbose: u8,
    /// Deny instead of prompting.
    pub no_ask: bool,
}

/// Top-level commands. The order here is the order in `--help`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run an agent inside the sandbox.
    ///
    /// Example: agentkeep run -- claude
    Run(RunArgs),

    /// Create, inspect and validate policy files.
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Proxy an MCP server: allowlist tools, pin versions, log every call.
    ///
    /// Example: agentkeep mcp-gateway --name github -- npx -y @modelcontextprotocol/server-github
    #[command(name = "mcp-gateway")]
    McpGateway(McpGatewayArgs),

    /// Scan a directory for agent attack surfaces (prompt injection, risky
    /// configs, over-broad permissions, unsafe CI workflows).
    Scan(ScanArgs),

    /// Browse, filter, replay and verify audit logs.
    Log(LogArgs),

    /// Produce a shareable summary of a session.
    Report(ReportArgs),

    /// Attach to a running session to answer approval prompts.
    Approve(ApproveArgs),

    /// Probe the sandbox backends available on this host and report what
    /// each can enforce.
    Doctor,

    /// Print version information for the binary and each component.
    Version,
}

impl Command {
    /// Human-readable command name, used in stub messages.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Run(_) => "run",
            Command::Policy(_) => "policy",
            Command::McpGateway(_) => "mcp-gateway",
            Command::Scan(_) => "scan",
            Command::Log(_) => "log",
            Command::Report(_) => "report",
            Command::Approve(_) => "approve",
            Command::Doctor => "doctor",
            Command::Version => "version",
        }
    }

    /// The phase of `PLAN.md` in which the command is scheduled to land.
    pub fn phase(&self) -> &'static str {
        match self {
            Command::Run(_) | Command::Policy(_) | Command::Approve(_) | Command::Doctor => {
                "Phase 1"
            }
            Command::Scan(_) => "Phase 3",
            Command::McpGateway(_) => "Phase 4",
            Command::Log(_) | Command::Report(_) => "Phase 5",
            Command::Version => "Phase 0",
        }
    }
}

/// Arguments for `agentkeep run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Agent preset to apply (claude-code, codex, opencode, gemini-cli, cline,
    /// goose). Auto-detected from the command when omitted.
    #[arg(long, value_name = "NAME")]
    pub preset: Option<String>,

    /// Force a sandbox backend instead of auto-selecting one.
    #[arg(long, value_enum)]
    pub backend: Option<BackendChoice>,

    /// Run even if the chosen backend cannot enforce every rule in the policy.
    /// Degradations are printed and written to the audit log.
    #[arg(long)]
    pub allow_degraded: bool,

    /// Project directory to expose read-write. Defaults to the git root of the
    /// current directory, or the current directory itself.
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,

    /// Extra domains to allow for this run only.
    #[arg(long = "allow-domain", value_name = "HOST")]
    pub allow_domains: Vec<String>,

    /// The agent command to run, after `--`.
    #[arg(required = true, last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Sandbox backends a user can force.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BackendChoice {
    /// Linux namespaces + Landlock + seccomp.
    Linux,
    /// macOS Seatbelt profile.
    Macos,
    /// Podman or Docker container (optionally with gVisor).
    Container,
    /// Windows: re-run inside WSL2 using the Linux backend.
    Wsl,
}

impl BackendChoice {
    /// The name used in policy files.
    pub fn policy_name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Container => "container",
            Self::Wsl => "wsl",
        }
    }
}

/// Subcommands of `agentkeep policy`.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Interactively create an agentkeep.toml in the current project.
    Init {
        /// Write a complete, commented default policy without asking questions.
        #[arg(long)]
        defaults: bool,
    },
    /// Print the fully merged, effective policy.
    Show {
        /// Print the built-in defaults only.
        #[arg(long)]
        defaults: bool,
    },
    /// Validate a policy file and report every problem with line numbers.
    Check {
        /// File to check. Defaults to the discovered policy.
        file: Option<PathBuf>,
    },
}

/// Arguments for `agentkeep mcp-gateway`.
#[derive(Debug, Args)]
pub struct McpGatewayArgs {
    /// Name of the server as it appears in the policy and lock file.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Lock file to pin the server's tool list against.
    #[arg(long, value_name = "FILE", default_value = "agentkeep.lock")]
    pub lock: PathBuf,

    /// The MCP server command to proxy, after `--`.
    #[arg(required = true, last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Arguments for `agentkeep scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Directory or file to scan. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = ScanFormat::Text)]
    pub format: ScanFormat,

    /// Exit non-zero when a finding at or above this severity exists.
    #[arg(long, value_enum, default_value_t = Severity::High)]
    pub fail_on: Severity,

    /// Additional rule directories to load.
    #[arg(long = "rules", value_name = "DIR")]
    pub rule_dirs: Vec<PathBuf>,
}

/// Scanner output formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScanFormat {
    /// Human-readable text with snippets.
    Text,
    /// Stable, versioned JSON.
    Json,
    /// SARIF 2.1.0 for GitHub code scanning.
    Sarif,
}

/// Finding severities, lowest to highest.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Severity {
    /// Informational.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// Arguments for `agentkeep log`.
#[derive(Debug, Args)]
pub struct LogArgs {
    /// Session id or path. Defaults to the most recent session.
    pub session: Option<String>,

    /// Verify the hash chain and exit instead of opening the viewer.
    #[arg(long)]
    pub verify: bool,

    /// Plain output instead of the terminal UI (forced when stdout is not a TTY).
    #[arg(long, value_enum)]
    pub format: Option<LogFormat>,
}

/// Non-interactive log output formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    /// One line per event.
    Text,
    /// Raw JSONL.
    Json,
}

/// Arguments for `agentkeep report`.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Session id or path. Defaults to the most recent session.
    pub session: Option<String>,

    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
    pub format: ReportFormat,

    /// Write to this file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Report formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ReportFormat {
    /// Markdown.
    Markdown,
    /// A single self-contained HTML file with no external assets.
    Html,
}

/// Arguments for `agentkeep approve`.
#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Path of the approval socket printed by `agentkeep run`.
    pub socket: PathBuf,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn run_requires_a_command_after_double_dash() {
        assert!(Cli::try_parse_from(["agentkeep", "run"]).is_err());
        let cli = Cli::try_parse_from(["agentkeep", "run", "--", "claude", "--help"]).ok();
        match cli.map(|c| c.command) {
            Some(Command::Run(args)) => assert_eq!(args.command, vec!["claude", "--help"]),
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn every_command_has_a_phase() {
        let cli = Cli::try_parse_from(["agentkeep", "scan", "."]).ok();
        match cli.map(|c| c.command) {
            Some(cmd) => assert!(cmd.phase().starts_with("Phase ")),
            None => panic!("scan failed to parse"),
        }
    }
}
