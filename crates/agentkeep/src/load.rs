//! Assemble the effective policy from every layer plus command-line
//! overrides.

use std::path::{Path, PathBuf};

use agentkeep_policy::decide::Compiled;
use agentkeep_policy::discover::{project_root, standard_layers};
use agentkeep_policy::merge::{merge, Layer, Source, Warning};
use agentkeep_policy::resolved::{Context, Policy};
use agentkeep_policy::schema::{FilesystemSection, NetworkSection, PolicyFile, SandboxSection};
use anyhow::{bail, Context as _, Result};

use crate::cli::{Globals, RunArgs};

/// The loaded policy and everything the CLI should tell the user about it.
pub struct Loaded {
    /// Merged, not yet resolved.
    pub merged: PolicyFile,
    /// Resolved.
    pub policy: Policy,
    /// Compiled matchers.
    pub compiled: Compiled,
    /// Warnings from merging.
    pub warnings: Vec<Warning>,
    /// Where layers came from, for the audit log.
    pub sources: Vec<String>,
}

/// Host environment facts needed to resolve a policy.
pub struct Host {
    /// `$HOME`.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, if set.
    pub xdg_config_home: Option<PathBuf>,
    /// Current directory.
    pub cwd: PathBuf,
}

impl Host {
    /// Read from the environment.
    pub fn detect() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .context("HOME is not set to an absolute path")?;
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        let cwd = std::env::current_dir().context("cannot read current directory")?;
        Ok(Self {
            home,
            xdg_config_home,
            cwd,
        })
    }
}

/// Build the command-line layer from `run` flags, if any flag was given.
fn cli_layer(args: Option<&RunArgs>) -> Option<Layer> {
    let args = args?;
    let mut file = PolicyFile {
        schema: Some(agentkeep_policy::SCHEMA_VERSION),
        ..Default::default()
    };
    let mut any = false;
    if args.backend.is_some() || args.allow_degraded {
        file.sandbox = Some(SandboxSection {
            backend: args.backend.map(|b| b.policy_name().to_string()),
            allow_degraded: args.allow_degraded.then_some(true),
            preset: None,
        });
        any = true;
    }
    if let Some(p) = &args.project {
        file.filesystem = Some(FilesystemSection {
            project: Some(p.to_string_lossy().into_owned()),
            ..Default::default()
        });
        any = true;
    }
    if !args.allow_domains.is_empty() {
        file.network = Some(NetworkSection {
            allow: args.allow_domains.clone(),
            ..Default::default()
        });
        any = true;
    }
    any.then_some(Layer {
        source: Source::Cli,
        base_dir: None,
        file,
    })
}

/// Load, merge, resolve and compile.
pub fn load(globals: &Globals, host: &Host, run_args: Option<&RunArgs>) -> Result<Loaded> {
    let mut layers = standard_layers(
        &host.home,
        host.xdg_config_home.as_deref(),
        &host.cwd,
        globals.policy.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(args) = run_args {
        if args.preset.is_some() {
            bail!("agent presets land in Phase 5; use [network] allow and [filesystem] read_write in agentkeep.toml for now");
        }
    }
    if let Some(cli) = cli_layer(run_args) {
        layers.push(cli);
    }
    let sources: Vec<String> = layers.iter().map(|l| l.source.to_string()).collect();
    let (merged, warnings) = merge(&layers);
    // A relative or default `project` means "this project": the git root of
    // the current directory, or the directory itself.
    let base_dir = project_root(&host.cwd);
    let ctx = Context {
        home: host.home.clone(),
        base_dir,
    };
    let policy = Policy::resolve(&merged, &ctx).map_err(|e| anyhow::anyhow!("policy: {e}"))?;
    check_project(&policy.project, &host.home)?;
    let compiled = Compiled::new(&policy);
    Ok(Loaded {
        merged,
        policy,
        compiled,
        warnings,
        sources,
    })
}

fn check_project(project: &Path, home: &Path) -> Result<()> {
    if project == Path::new("/") {
        bail!("refusing to use / as the project directory");
    }
    if project == home {
        bail!(
            "refusing to use your home directory ({}) as the project; run agentkeep from a project subdirectory or set [filesystem] project",
            home.display()
        );
    }
    if home.starts_with(project) {
        bail!(
            "refusing a project directory ({}) that contains your home directory",
            project.display()
        );
    }
    Ok(())
}
