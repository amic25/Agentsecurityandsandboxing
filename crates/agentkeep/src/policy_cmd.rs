//! `agentkeep policy init | show | check`.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use agentkeep_policy::defaults::{DEFAULT_POLICY, PROJECT_TEMPLATE};
use agentkeep_policy::discover::{load_file, PROJECT_FILE_NAME};
use agentkeep_policy::merge::{merge, Source};
use agentkeep_policy::resolved::{Context, Policy};
use anyhow::{bail, Context as _, Result};

use crate::cli::{Globals, PolicyCommand};
use crate::load::{self, Host};
use crate::ui;

/// Dispatch.
pub fn run(globals: &Globals, cmd: PolicyCommand) -> Result<ExitCode> {
    match cmd {
        PolicyCommand::Init { defaults } => init(defaults),
        PolicyCommand::Show { defaults } => show(globals, defaults),
        PolicyCommand::Check { file } => check(globals, file.as_deref()),
    }
}

fn prompt_list(question: &str) -> Result<Vec<String>> {
    eprint!("{question}\n  > ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn toml_array(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
        .collect();
    format!("[{}]", quoted.join(", "))
}

fn init(defaults: bool) -> Result<ExitCode> {
    let path = Path::new(PROJECT_FILE_NAME);
    if path.exists() {
        bail!(
            "{} already exists; edit it or remove it first",
            path.display()
        );
    }
    let mut text = PROJECT_TEMPLATE.to_string();
    if !defaults {
        eprintln!("{}", ui::bold("agentkeep policy init"));
        eprintln!("Answers become the project's agentkeep.toml. Press Enter to skip a question.\n");
        let domains = prompt_list("Extra domains the agent must reach (comma-separated, e.g. api.github.com, *.npmjs.org):")?;
        let rw = prompt_list("Extra read-write paths (e.g. ~/.cache/pip):")?;
        let pass =
            prompt_list("Secret environment variables the agent needs (e.g. ANTHROPIC_API_KEY):")?;
        for (needle, items) in [
            ("# matches subdomains only.\nallow = []", domains),
            ("read_only = []\nread_write = []", rw),
            ("# Secrets the agent needs. DLP binds each one to its provider's domains.\npass = []", pass),
        ] {
            if items.is_empty() {
                continue;
            }
            let replacement = needle.replace("= []", &format!("= {}", toml_array(&items)));
            // Only the last `= []` in the needle is the target.
            let replacement = if needle.matches("= []").count() > 1 {
                let idx = needle.rfind("= []").unwrap_or(0);
                format!("{}= {}", &needle[..idx], toml_array(&items))
            } else {
                replacement
            };
            text = text.replacen(needle, &replacement, 1);
        }
    }
    // Make sure what we are about to write parses and resolves.
    let file = agentkeep_policy::parse_str(&text, PROJECT_FILE_NAME)?;
    let host = Host::detect()?;
    Policy::resolve(
        &file,
        &Context {
            home: host.home.clone(),
            base_dir: host.cwd.clone(),
        },
    )
    .map_err(|e| anyhow::anyhow!("generated policy is invalid: {e}"))?;
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    eprintln!("wrote {}", path.display());
    Ok(ExitCode::SUCCESS)
}

fn show(globals: &Globals, defaults: bool) -> Result<ExitCode> {
    if defaults {
        print!("{DEFAULT_POLICY}");
        return Ok(ExitCode::SUCCESS);
    }
    let host = Host::detect()?;
    let loaded = load::load(globals, &host, None)?;
    println!("# Effective policy, merged from:");
    for s in &loaded.sources {
        println!("#   - {s}");
    }
    for w in &loaded.warnings {
        println!("# WARNING ({}): {}", w.source, w.message);
    }
    println!("# project = {}", loaded.policy.project.display());
    println!();
    print!("{}", toml::to_string_pretty(&loaded.merged)?);
    Ok(ExitCode::SUCCESS)
}

fn check(globals: &Globals, file: Option<&Path>) -> Result<ExitCode> {
    let host = Host::detect()?;
    if let Some(path) = file {
        let layer = load_file(path, Source::Project(path.to_path_buf()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let layers = [agentkeep_policy::discover::defaults_layer(), layer];
        let (merged, warnings) = merge(&layers);
        let base_dir = host
            .cwd
            .join(path)
            .parent()
            .map_or_else(|| host.cwd.clone(), Path::to_path_buf);
        Policy::resolve(
            &merged,
            &Context {
                home: host.home.clone(),
                base_dir,
            },
        )
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        for w in &warnings {
            ui::warn(&format!("{}: {}", w.source, w.message));
        }
        println!("{}: OK", path.display());
    } else {
        let loaded = load::load(globals, &host, None)?;
        for w in &loaded.warnings {
            ui::warn(&format!("{}: {}", w.source, w.message));
        }
        println!("effective policy: OK ({} layers)", loaded.sources.len());
    }
    Ok(ExitCode::SUCCESS)
}
