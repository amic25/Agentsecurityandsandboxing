//! Assemble the effective policy from every layer plus command-line
//! overrides.

use std::path::{Path, PathBuf};

use agentkeep_policy::decide::Compiled;
use agentkeep_policy::discover::{
    defaults_layer, find_project_file, global_file, load_file, project_root,
};
use agentkeep_policy::merge::{merge, Layer, Source, Warning};
use agentkeep_policy::resolved::{Context, Policy};
use agentkeep_policy::schema::{FilesystemSection, NetworkSection, PolicyFile, SandboxSection};
use agentkeep_policy::trust::{restrict_untrusted, TrustStore, STORE_FILE_NAME};
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
    /// Trust status of the project policy file, when there is one.
    pub project_trust: Option<ProjectTrust>,
}

/// Whether the project policy file applied in full, and if not, what was
/// ignored (threat model S1).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectTrust {
    /// The project policy file.
    pub path: PathBuf,
    /// Why it applies in full, or `None` when only its tightening settings did.
    pub trusted_by: Option<&'static str>,
    /// Loosening settings that were ignored because the file is untrusted.
    pub ignored: Vec<String>,
}

/// The trust store, next to the global policy file.
pub fn trust_store_path(host: &Host) -> PathBuf {
    global_file(&host.home, host.xdg_config_home.as_deref()).with_file_name(STORE_FILE_NAME)
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
    let mut layers = vec![defaults_layer()];
    let global = global_file(&host.home, host.xdg_config_home.as_deref());
    if global.is_file() {
        layers.push(
            load_file(&global, Source::Global(global.clone()))
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        );
    }
    let mut extra_warnings = Vec::new();
    let project_trust = match globals
        .policy
        .clone()
        .or_else(|| find_project_file(&host.cwd))
    {
        Some(path) => {
            let named = globals.policy.is_some();
            let trust_flag = run_args.is_some_and(|a| a.trust_project);
            let (layer, trust) = project_layer(&path, host, &layers, named, trust_flag)?;
            if trust.trusted_by.is_none() && !trust.ignored.is_empty() {
                extra_warnings.push(Warning {
                    source: layer.source.clone(),
                    message: format!(
                        "this project policy is not trusted, so settings that would loosen the sandbox were ignored: {}. Review the file, then run `agentkeep policy trust` (or pass --trust-project for one run)",
                        trust.ignored.join(", ")
                    ),
                });
            }
            layers.push(layer);
            Some(trust)
        }
        None => None,
    };
    if let Some(args) = run_args {
        if args.preset.is_some() {
            bail!("agent presets land in Phase 5; use [network] allow and [filesystem] read_write in agentkeep.toml for now");
        }
    }
    if let Some(cli) = cli_layer(run_args) {
        layers.push(cli);
    }
    let sources: Vec<String> = layers.iter().map(|l| l.source.to_string()).collect();
    let (merged, mut warnings) = merge(&layers);
    warnings.extend(extra_warnings);
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
        project_trust,
    })
}

/// Read the project policy once, decide whether it is trusted, and restrict
/// it to its tightening settings when it is not. Reading the bytes once and
/// parsing those same bytes means the trusted content is the content used.
fn project_layer(
    path: &Path,
    host: &Host,
    lower: &[Layer],
    named: bool,
    trust_flag: bool,
) -> Result<(Layer, ProjectTrust)> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    let file = agentkeep_policy::parse_str(text, &path.display().to_string())?;
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        host.cwd.join(path)
    };
    let trusted_by = if named {
        Some("named with --policy")
    } else if trust_flag {
        Some("--trust-project")
    } else {
        let store =
            TrustStore::load(&trust_store_path(host)).map_err(|e| anyhow::anyhow!("{e}"))?;
        store
            .is_trusted(&abs, &bytes)
            .then_some("trusted with `agentkeep policy trust`")
    };
    let (file, ignored) = if trusted_by.is_some() {
        (file, Vec::new())
    } else {
        let (current, _) = merge(lower);
        restrict_untrusted(&file, &current)
    };
    let layer = Layer {
        source: Source::Project(abs.clone()),
        base_dir: abs.parent().map(Path::to_path_buf),
        file,
    };
    Ok((
        layer,
        ProjectTrust {
            path: abs,
            trusted_by,
            ignored,
        },
    ))
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
