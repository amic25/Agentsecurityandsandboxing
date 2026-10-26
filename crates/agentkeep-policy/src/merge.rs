//! Layered merging with tightening-only semantics.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentkeep_common::paths;

use crate::schema::{
    ApprovalSection, AuditSection, CommandsSection, DlpSection, EnvSection, FilesystemSection,
    LimitsSection, McpSection, NetworkSection, PolicyFile, SandboxSection,
};

/// Where a layer came from. Determines whether `[override]` is honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Compiled-in defaults.
    Defaults,
    /// An agent preset.
    Preset(String),
    /// The global user file.
    Global(PathBuf),
    /// The project file. The only source whose `[override]` is honoured.
    Project(PathBuf),
    /// Command-line flags.
    Cli,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Defaults => write!(f, "built-in defaults"),
            Self::Preset(n) => write!(f, "preset `{n}`"),
            Self::Global(p) | Self::Project(p) => write!(f, "{}", p.display()),
            Self::Cli => write!(f, "command line"),
        }
    }
}

/// One policy layer.
#[derive(Debug, Clone)]
pub struct Layer {
    /// Provenance.
    pub source: Source,
    /// Directory a relative `filesystem.project` resolves against, if any.
    pub base_dir: Option<PathBuf>,
    /// The parsed file.
    pub file: PolicyFile,
}

/// Something the user should see at startup. Never fatal, never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Layer that caused it.
    pub source: Source,
    /// Human-readable text.
    pub message: String,
}

/// Merge layers, lowest priority first.
///
/// Scalars: last layer that sets a value wins. Lists: union in order, no
/// duplicates. `hidden`, `network.deny`, `commands.deny` and `mcp.deny_tools`
/// only grow, except through a project-file `[override]` with
/// `acknowledge = true`; each removal produces a [`Warning`].
#[allow(clippy::too_many_lines)]
pub fn merge(layers: &[Layer]) -> (PolicyFile, Vec<Warning>) {
    let mut out = PolicyFile::default();
    let mut warnings = Vec::new();

    for layer in layers {
        let f = &layer.file;
        if f.schema.is_some() {
            out.schema = f.schema;
        }
        if let Some(s) = &f.sandbox {
            let o = out.sandbox.get_or_insert_with(SandboxSection::default);
            set(&mut o.backend, s.backend.as_ref());
            set(&mut o.allow_degraded, s.allow_degraded.as_ref());
            set(&mut o.preset, s.preset.as_ref());
        }
        if let Some(s) = &f.filesystem {
            let o = out
                .filesystem
                .get_or_insert_with(FilesystemSection::default);
            if let Some(project) = &s.project {
                // Resolve relative project paths against the layer that wrote
                // them, so a project file means "this project" regardless of
                // where agentkeep is invoked from.
                let p = PathBuf::from(project);
                let resolved = match &layer.base_dir {
                    Some(base) if !p.is_absolute() && !project.starts_with('~') => {
                        paths::normalize(&base.join(p))
                            .to_string_lossy()
                            .into_owned()
                    }
                    _ => project.clone(),
                };
                o.project = Some(resolved);
            }
            union(&mut o.read_only, &s.read_only);
            union(&mut o.read_write, &s.read_write);
            union(&mut o.hidden, &s.hidden);
        }
        if let Some(s) = &f.env {
            let o = out.env.get_or_insert_with(EnvSection::default);
            union(&mut o.allow, &s.allow);
            union(&mut o.pass, &s.pass);
            map_merge(&mut o.set, &s.set);
        }
        if let Some(s) = &f.network {
            let o = out.network.get_or_insert_with(NetworkSection::default);
            union(&mut o.allow, &s.allow);
            union(&mut o.ask, &s.ask);
            union(&mut o.deny, &s.deny);
            set(&mut o.tls_inspect, s.tls_inspect.as_ref());
            union(&mut o.passthrough, &s.passthrough);
            set(&mut o.allow_private, s.allow_private.as_ref());
            union(&mut o.trusted_cas, &s.trusted_cas);
        }
        if let Some(s) = &f.dlp {
            let o = out.dlp.get_or_insert_with(DlpSection::default);
            set(&mut o.enabled, s.enabled.as_ref());
            union(&mut o.block_values, &s.block_values);
            union(&mut o.report_only, &s.report_only);
            for (k, v) in &s.allow_provider_keys_to {
                union(o.allow_provider_keys_to.entry(k.clone()).or_default(), v);
            }
        }
        if let Some(s) = &f.commands {
            let o = out.commands.get_or_insert_with(CommandsSection::default);
            union(&mut o.ask, &s.ask);
            union(&mut o.deny, &s.deny);
        }
        if let Some(s) = &f.mcp {
            let o = out.mcp.get_or_insert_with(McpSection::default);
            union(&mut o.allow_tools, &s.allow_tools);
            union(&mut o.deny_tools, &s.deny_tools);
            set(&mut o.pin, s.pin.as_ref());
            set(&mut o.block_injection, s.block_injection.as_ref());
            for (k, v) in &s.args {
                o.args.insert(k.clone(), v.clone());
            }
        }
        if let Some(s) = &f.limits {
            let o = out.limits.get_or_insert_with(LimitsSection::default);
            set(&mut o.cpu_percent, s.cpu_percent.as_ref());
            set(&mut o.memory, s.memory.as_ref());
            set(&mut o.pids, s.pids.as_ref());
            set(&mut o.wall_time, s.wall_time.as_ref());
        }
        if let Some(s) = &f.approval {
            let o = out.approval.get_or_insert_with(ApprovalSection::default);
            if !s.transport.is_empty() {
                o.transport.clone_from(&s.transport);
            }
            set(&mut o.timeout, s.timeout.as_ref());
        }
        if let Some(s) = &f.audit {
            let o = out.audit.get_or_insert_with(AuditSection::default);
            set(&mut o.dir, s.dir.as_ref());
            set(&mut o.redact, s.redact.as_ref());
        }
        if let Some(ov) = &f.r#override {
            let is_project = matches!(layer.source, Source::Project(_));
            let acknowledged = ov.acknowledge == Some(true);
            let has_entries = !ov.unhide.is_empty()
                || !ov.undeny_domains.is_empty()
                || !ov.undeny_commands.is_empty();
            if !has_entries {
                // Nothing to do.
            } else if !is_project {
                warnings.push(Warning {
                    source: layer.source.clone(),
                    message: "[override] is only honoured in the project file; ignored".into(),
                });
            } else if !acknowledged {
                warnings.push(Warning {
                    source: layer.source.clone(),
                    message: "[override] needs `acknowledge = true` to take effect; ignored".into(),
                });
            } else {
                if let Some(fs) = out.filesystem.as_mut() {
                    remove_each(
                        &mut fs.hidden,
                        &ov.unhide,
                        "hidden",
                        &layer.source,
                        &mut warnings,
                    );
                }
                if let Some(net) = out.network.as_mut() {
                    remove_each(
                        &mut net.deny,
                        &ov.undeny_domains,
                        "network.deny",
                        &layer.source,
                        &mut warnings,
                    );
                }
                if let Some(c) = out.commands.as_mut() {
                    remove_each(
                        &mut c.deny,
                        &ov.undeny_commands,
                        "commands.deny",
                        &layer.source,
                        &mut warnings,
                    );
                }
            }
        }
    }
    (out, warnings)
}

fn set<T: Clone>(dst: &mut Option<T>, src: Option<&T>) {
    if let Some(v) = src {
        *dst = Some(v.clone());
    }
}

fn union(dst: &mut Vec<String>, src: &[String]) {
    for s in src {
        if !dst.contains(s) {
            dst.push(s.clone());
        }
    }
}

fn map_merge(dst: &mut BTreeMap<String, String>, src: &BTreeMap<String, String>) {
    for (k, v) in src {
        dst.insert(k.clone(), v.clone());
    }
}

fn remove_each(
    list: &mut Vec<String>,
    remove: &[String],
    what: &str,
    source: &Source,
    warnings: &mut Vec<Warning>,
) {
    for r in remove {
        let before = list.len();
        list.retain(|x| x != r);
        let message = if list.len() == before {
            format!("[override] `{r}` is not in {what}; nothing removed")
        } else {
            format!("[override] removed `{r}` from {what}: this weakens a built-in protection")
        };
        warnings.push(Warning {
            source: source.clone(),
            message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;

    fn layer(source: Source, text: &str) -> Layer {
        Layer {
            source,
            base_dir: Some(PathBuf::from("/p")),
            file: parse_str(text, "t").unwrap(),
        }
    }

    #[test]
    fn lists_union_and_scalars_last_win() {
        let (m, w) = merge(&[
            layer(
                Source::Defaults,
                "schema=1\n[network]\nallow=['a.example']\ntls_inspect=true\n",
            ),
            layer(
                Source::Project(PathBuf::from("/p/agentkeep.toml")),
                "schema=1\n[network]\nallow=['b.example','a.example']\ntls_inspect=false\n",
            ),
        ]);
        let n = m.network.unwrap();
        assert_eq!(n.allow, vec!["a.example", "b.example"]);
        assert_eq!(n.tls_inspect, Some(false));
        assert!(w.is_empty());
    }

    #[test]
    fn hidden_cannot_be_removed_without_override() {
        let (m, w) = merge(&[
            layer(
                Source::Defaults,
                "schema=1\n[filesystem]\nhidden=['~/.ssh']\n",
            ),
            layer(
                Source::Global(PathBuf::from("/g")),
                "schema=1\n[override]\nacknowledge=true\nunhide=['~/.ssh']\n",
            ),
            layer(
                Source::Project(PathBuf::from("/p/a.toml")),
                "schema=1\n[override]\nunhide=['~/.ssh']\n",
            ),
        ]);
        assert_eq!(m.filesystem.unwrap().hidden, vec!["~/.ssh"]);
        assert_eq!(w.len(), 2);
        assert!(w[0].message.contains("only honoured in the project file"));
        assert!(w[1].message.contains("acknowledge"));
    }

    #[test]
    fn project_override_removes_and_warns() {
        let (m, w) = merge(&[
            layer(Source::Defaults, "schema=1\n[filesystem]\nhidden=['~/.ssh','~/.npmrc']\n[commands]\ndeny=['sudo *']\n"),
            layer(Source::Project(PathBuf::from("/p/a.toml")), "schema=1\n[override]\nacknowledge=true\nunhide=['~/.npmrc','~/.nothing']\nundeny_commands=['sudo *']\n"),
        ]);
        assert_eq!(m.filesystem.unwrap().hidden, vec!["~/.ssh"]);
        assert!(m.commands.unwrap().deny.is_empty());
        assert_eq!(w.len(), 3);
        assert!(w[0].message.contains("weakens"));
        assert!(w[1].message.contains("nothing removed"));
    }

    #[test]
    #[cfg(unix)] // POSIX path fixture
    fn relative_project_resolves_against_layer_dir() {
        let (m, _) = merge(&[Layer {
            source: Source::Project(PathBuf::from("/x/y/agentkeep.toml")),
            base_dir: Some(PathBuf::from("/x/y")),
            file: parse_str("schema=1\n[filesystem]\nproject='sub/../.'\n", "t").unwrap(),
        }]);
        assert_eq!(m.filesystem.unwrap().project.as_deref(), Some("/x/y"));
    }
}
