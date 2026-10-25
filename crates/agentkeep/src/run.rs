//! `agentkeep run -- <command>`: build the launch plan from the policy,
//! start the approval channel and audit log, launch the sandbox, wait.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use agentkeep_common::secrets::looks_like_secret_name;
use agentkeep_policy::decide::{Decision, Request};
use agentkeep_policy::resolved::Policy;
use agentkeep_sandbox::{LaunchPlan, Limits, Mount, MountMode, ShimConfig};
use anyhow::{Context, Result};

use crate::approval::{LogSink, Server};
use crate::cli::{Globals, RunArgs};
use crate::load::{self, Host, Loaded};
use crate::ui;

use crate::doctor::EXIT_NO_BACKEND;

/// Inside-sandbox locations.
const SHIM_DIR: &str = "/run/agentkeep/bin";
const SOCKET_PATH: &str = "/run/agentkeep/approve.sock";

/// Run a command in the sandbox.
///
/// Long by design: this is the session's lifecycle in order, and reading it
/// top to bottom is how a reviewer checks that nothing starts before the
/// audit log and approval channel exist.
#[allow(clippy::too_many_lines)]
pub fn run(globals: &Globals, args: &RunArgs) -> Result<ExitCode> {
    let host = Host::detect()?;
    let loaded = load::load(globals, &host, Some(args))?;
    for w in &loaded.warnings {
        if w.message.contains("weakens") {
            ui::danger(&format!("{}: {}", w.source, w.message));
        } else {
            ui::warn(&format!("{}: {}", w.source, w.message));
        }
    }

    // Backend.
    let wanted = args.backend.map_or_else(
        || loaded.policy.backend.name().to_string(),
        |b| b.policy_name().to_string(),
    );
    let (backend, probe) = match agentkeep_sandbox::select(&wanted) {
        Ok(x) => x,
        Err(rejected) => {
            ui::error("no sandbox backend is available on this host:");
            for (name, p) in rejected {
                if let agentkeep_sandbox::Probe::Unavailable { reason } = p {
                    eprintln!("  {name}: {reason}");
                }
            }
            eprintln!("  (macOS and container backends land in Phase 2)");
            return Ok(ExitCode::from(EXIT_NO_BACKEND));
        }
    };
    for d in probe.degradations() {
        ui::warn(&format!("{}: {} -> {}", d.control, d.reason, d.fallback));
    }

    // Session resources on the host.
    let session_id = agentkeep_audit::time::session_id(std::process::id());
    let scratch = tempfile::Builder::new()
        .prefix("agentkeep.")
        .tempdir()
        .context("create session scratch directory")?;
    let root_base = scratch.path().join("root");
    std::fs::create_dir(&root_base)?;
    let socket_path = scratch.path().join("approve.sock");

    let session_dir = loaded.policy.audit_dir.join(&session_id);
    let writer = agentkeep_audit::Writer::create(&session_dir)
        .with_context(|| format!("create audit log in {}", session_dir.display()))?;
    let log = Arc::new(Mutex::new(Some(writer)));

    // Plan.
    let (env, scrubbed) = build_env(&loaded, &host);
    let plan = build_plan(
        &loaded,
        &host,
        args,
        &session_id,
        &root_base,
        &socket_path,
        env,
    )?;

    append(
        &log,
        "session.start",
        serde_json::json!({
            "session": session_id,
            "command": plan.command,
            "project": plan.project,
            "cwd": plan.cwd,
            "backend": backend.name(),
            "capabilities": probe.capabilities(),
            "degradations": probe.degradations(),
            "policy_sources": loaded.sources,
            "policy_warnings": loaded.warnings.iter().map(|w| format!("{}: {}", w.source, w.message)).collect::<Vec<_>>(),
            "policy": toml::to_string(&loaded.merged).unwrap_or_default(),
            "env_scrubbed": scrubbed.plain,
            "env_scrubbed_secrets": scrubbed.secret_like,
            "mounts": plan.mounts,
            "limits": plan.limits,
        }),
    );

    // Approval channel must exist before launch (it is bind-mounted in).
    let mut server = Server::bind(
        &socket_path,
        loaded.compiled.clone(),
        loaded.policy.approval_transports.clone(),
        loaded.policy.approval_timeout,
        globals.no_ask,
        LogSink(Arc::clone(&log)),
    )?;

    if globals.verbose > 0 {
        ui::info(&format!("session {session_id}"));
        ui::info(&format!(
            "audit log {}",
            session_dir.join(agentkeep_audit::EVENTS_FILE).display()
        ));
        ui::info(&format!(
            "approval socket {} (agentkeep approve <path>)",
            server.path().display()
        ));
    }

    // Launch while still single-threaded, then start the helper threads.
    let mut handle = match backend.launch(&plan) {
        Ok(h) => h,
        Err(e) => {
            append(
                &log,
                "session.end",
                serde_json::json!({"error": e.to_string()}),
            );
            return Err(e).context("launch sandbox");
        }
    };
    #[cfg(target_os = "linux")]
    agentkeep_sandbox::linux::install_supervisor_signals();
    server.start();
    let _timer = loaded.policy.limits.wall_time.map(|t| handle.kill_after(t));

    let status = handle.wait().context("wait for sandbox")?;
    let code = status.shell_code();
    append(
        &log,
        "session.end",
        serde_json::json!({"status": status.to_string(), "code": code}),
    );
    if globals.verbose > 0 || !matches!(status, agentkeep_sandbox::ExitStatus::Code(_)) {
        ui::info(&format!("session {session_id} ended: {status}"));
    }
    drop(scratch);
    Ok(ExitCode::from(
        u8::try_from(code.clamp(0, 255)).unwrap_or(1),
    ))
}

fn append(log: &Arc<Mutex<Option<agentkeep_audit::Writer>>>, kind: &str, data: serde_json::Value) {
    if let Ok(mut g) = log.lock() {
        if let Some(w) = g.as_mut() {
            if let Err(e) = w.append(kind, data) {
                ui::warn(&format!("audit log write failed: {e}"));
            }
        }
    }
}

/// Names dropped from the environment, split by whether they looked secret.
#[derive(Default)]
struct Scrubbed {
    plain: Vec<String>,
    secret_like: Vec<String>,
}

fn build_env(loaded: &Loaded, host: &Host) -> (BTreeMap<String, String>, Scrubbed) {
    let mut env = BTreeMap::new();
    let mut scrubbed = Scrubbed::default();
    for (name, value) in std::env::vars() {
        match loaded.compiled.decide(&Request::Env { name: &name }) {
            Decision::Allow { .. } => {
                env.insert(name, value);
            }
            _ => {
                if looks_like_secret_name(&name) {
                    scrubbed.secret_like.push(name);
                } else {
                    scrubbed.plain.push(name);
                }
            }
        }
    }
    for (k, v) in &loaded.policy.env_set {
        env.insert(k.clone(), v.clone());
    }
    let path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    env.insert("PATH".into(), format!("{SHIM_DIR}:{path}"));
    env.insert("HOME".into(), host.home.to_string_lossy().into_owned());
    let user = user_name();
    env.insert("USER".into(), user.clone());
    env.insert("LOGNAME".into(), user);
    env.insert(
        "XDG_RUNTIME_DIR".into(),
        format!("/run/user/{}", agentkeep_sandbox::linux_inner_uid()),
    );
    env.insert("AGENTKEEP_SOCKET".into(), SOCKET_PATH.into());
    env.insert("AGENTKEEP_SHIM_DIR".into(), SHIM_DIR.into());
    env.insert("AGENTKEEP".into(), "1".into());
    (env, scrubbed)
}

fn user_name() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| {
            !u.is_empty()
                && u.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .unwrap_or_else(|| "agent".into())
}

/// Commands worth shimming: the first word of every ask/deny pattern that
/// is a plain program name.
fn shim_commands(policy: &Policy) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pat in policy.cmd_ask.iter().chain(policy.cmd_deny.iter()) {
        let Some(first) = pat.split_whitespace().next() else {
            continue;
        };
        if first.contains(['*', '?', '[', '/']) || first.is_empty() {
            continue;
        }
        if !out.iter().any(|c| c == first) {
            out.push(first.to_string());
        }
    }
    out
}

fn build_plan(
    loaded: &Loaded,
    host: &Host,
    args: &RunArgs,
    session_id: &str,
    root_base: &Path,
    socket_path: &Path,
    env: BTreeMap<String, String>,
) -> Result<LaunchPlan> {
    let policy = &loaded.policy;
    let project = policy.project.clone();
    let mut mounts = Vec::new();

    for p in &policy.read_only {
        if p.exists() {
            mounts.push(Mount {
                source: p.clone(),
                target: p.clone(),
                mode: MountMode::ReadOnly,
                size: None,
            });
        } else if p.starts_with(&host.home) || p.starts_with(&project) {
            ui::warn(&format!(
                "read_only path {} does not exist; skipped",
                p.display()
            ));
        }
    }
    mounts.push(Mount {
        source: PathBuf::new(),
        target: host.home.clone(),
        mode: MountMode::Tmpfs,
        size: None,
    });
    mounts.push(Mount {
        source: project.clone(),
        target: project.clone(),
        mode: MountMode::ReadWrite,
        size: None,
    });
    for p in &policy.read_write {
        if p.exists() {
            mounts.push(Mount {
                source: p.clone(),
                target: p.clone(),
                mode: MountMode::ReadWrite,
                size: None,
            });
        } else {
            ui::warn(&format!(
                "read_write path {} does not exist; skipped",
                p.display()
            ));
        }
    }
    for p in &policy.hidden {
        mounts.push(Mount {
            source: PathBuf::new(),
            target: p.clone(),
            mode: MountMode::Hidden,
            size: None,
        });
    }
    for t in ["/tmp", "/var/tmp"] {
        mounts.push(Mount {
            source: PathBuf::new(),
            target: PathBuf::from(t),
            mode: MountMode::Tmpfs,
            size: None,
        });
    }

    let cwd = if host.cwd.starts_with(&project) {
        host.cwd.clone()
    } else {
        project.clone()
    };
    let self_exe = std::env::current_exe().context("locate agentkeep binary")?;

    Ok(LaunchPlan {
        session_id: session_id.to_string(),
        mounts,
        project,
        home: host.home.clone(),
        env,
        cwd,
        command: args.command.clone(),
        limits: Limits {
            cpu_percent: policy.limits.cpu_percent,
            memory: policy.limits.memory,
            pids: policy.limits.pids,
            wall_time_secs: policy.limits.wall_time.map(|d| d.as_secs()),
        },
        hostname: "agentkeep".into(),
        self_exe,
        root_base: root_base.to_path_buf(),
        user_name: user_name(),
        approval_socket: Some(socket_path.to_path_buf()),
        shim: Some(ShimConfig {
            dir: PathBuf::from(SHIM_DIR),
            commands: shim_commands(policy),
            socket: PathBuf::from(SOCKET_PATH),
        }),
        landlock: true,
        seccomp: true,
        inner_uid: agentkeep_sandbox::linux_inner_uid(),
        inner_gid: agentkeep_sandbox::linux_inner_uid(),
    })
}
