//! The approval channel: command shims and future proxy/MCP checks ask the
//! supervisor over a Unix socket; humans answer on the terminal or through
//! `agentkeep approve`. No answer within the timeout means deny.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use agentkeep_policy::decide::{Compiled, Decision, Request};
use agentkeep_policy::resolved::Transport;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{ApproveArgs, Globals};
use crate::ui;

/// A message from a shim or an approver client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientMessage {
    /// A shimmed command is about to run.
    Exec {
        /// Argument vector.
        argv: Vec<String>,
        /// Working directory inside the sandbox.
        cwd: String,
    },
    /// This connection wants to answer prompts.
    Approver,
}

/// The supervisor's answer to an `Exec` message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecReply {
    /// `allow` or `deny`.
    pub decision: String,
    /// Rule or reason.
    pub rule: String,
}

/// A prompt pushed to an approver client.
#[derive(Debug, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Correlates the answer.
    pub id: u64,
    /// What is being asked.
    pub prompt: String,
    /// Rule that asked.
    pub rule: String,
}

/// An approver's answer.
#[derive(Debug, Serialize, Deserialize)]
pub struct AnswerMessage {
    /// From the prompt.
    pub id: u64,
    /// `y` or `n`.
    pub answer: String,
}

/// Something the server logs.
pub struct LogSink(pub Arc<Mutex<Option<agentkeep_audit::Writer>>>);

impl LogSink {
    fn log(&self, kind: &str, data: serde_json::Value) {
        if let Ok(mut g) = self.0.lock() {
            if let Some(w) = g.as_mut() {
                if let Err(e) = w.append(kind, data) {
                    ui::warn(&format!("audit log write failed: {e}"));
                }
            }
        }
    }
}

/// State shared by the socket server and anything else that needs to ask a
/// human (the egress proxy).
pub struct Shared {
    compiled: Compiled,
    transports: Vec<Transport>,
    timeout: Duration,
    no_ask: bool,
    approvers: Mutex<Vec<UnixStream>>,
    next_id: Mutex<u64>,
    log: LogSink,
}

impl Shared {
    /// Ask a human through the configured transports; deny on timeout or
    /// when nobody can answer.
    pub fn ask_human(self: &Arc<Self>, prompt: &str, rule: &str) -> bool {
        ask(self, prompt, rule)
    }

    /// Record an event in the audit log.
    pub fn log(&self, kind: &str, data: serde_json::Value) {
        self.log.log(kind, data);
    }
}

/// Which socket a connection arrived on. The two are never interchangeable:
/// the exec socket is bind-mounted into the sandbox and may only *request*
/// decisions; the approver socket stays on the host and is the only place a
/// human answer can come from (threat model B3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Shims inside the sandbox.
    Exec,
    /// `agentkeep approve` clients on the host.
    Approver,
}

/// The server half, owned by `agentkeep run`.
pub struct Server {
    shared: Arc<Shared>,
    exec_listener: Option<UnixListener>,
    approver_listener: Option<UnixListener>,
    approver_path: PathBuf,
}

impl Server {
    /// Bind both sockets. Call before launching the sandbox so the exec
    /// socket exists to be bind-mounted. `approver_path` must never be made
    /// visible inside the sandbox.
    pub fn bind(
        exec_path: &Path,
        approver_path: &Path,
        compiled: Compiled,
        transports: Vec<Transport>,
        timeout: Duration,
        no_ask: bool,
        log: LogSink,
    ) -> Result<Self> {
        let exec_listener = UnixListener::bind(exec_path)
            .with_context(|| format!("bind {}", exec_path.display()))?;
        let approver_listener = UnixListener::bind(approver_path)
            .with_context(|| format!("bind {}", approver_path.display()))?;
        // Owner-only: other local users must not answer prompts either.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(approver_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod {}", approver_path.display()))?;
        }
        Ok(Self {
            shared: Arc::new(Shared {
                compiled,
                transports,
                timeout,
                no_ask,
                approvers: Mutex::new(Vec::new()),
                next_id: Mutex::new(1),
                log,
            }),
            exec_listener: Some(exec_listener),
            approver_listener: Some(approver_listener),
            approver_path: approver_path.to_path_buf(),
        })
    }

    /// Path of the host-only approver socket, for `agentkeep approve`.
    pub fn approver_path(&self) -> &Path {
        &self.approver_path
    }

    /// The shared state, for the proxy hooks.
    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// Start accepting connections on background threads.
    pub fn start(&mut self) {
        for (listener, role) in [
            (self.exec_listener.take(), Role::Exec),
            (self.approver_listener.take(), Role::Approver),
        ] {
            let Some(listener) = listener else { continue };
            let shared = Arc::clone(&self.shared);
            thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(stream) = conn else { continue };
                    let shared = Arc::clone(&shared);
                    thread::spawn(move || handle(stream, &shared, role));
                }
            });
        }
    }
}

fn handle(mut stream: UnixStream, shared: &Arc<Shared>, role: Role) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut line = String::new();
    if BufReader::new(stream.try_clone().ok().map_or_else(
        || Box::new(std::io::empty()) as Box<dyn Read>,
        |s| Box::new(s) as Box<dyn Read>,
    ))
    .read_line(&mut line)
    .is_err()
    {
        return;
    }
    let Ok(msg) = serde_json::from_str::<ClientMessage>(&line) else {
        let _ = writeln!(
            stream,
            "{{\"decision\":\"deny\",\"rule\":\"malformed request\"}}"
        );
        return;
    };
    match (msg, role) {
        (ClientMessage::Approver, Role::Approver) => {
            let _ = stream.set_read_timeout(None);
            if let Ok(mut a) = shared.approvers.lock() {
                a.push(stream);
            }
        }
        (ClientMessage::Approver, Role::Exec) => {
            // A sandboxed process tried to become its own approver.
            shared.log.log(
                "approval.refused",
                serde_json::json!({"reason": "approver registration on the sandbox socket"}),
            );
            let _ = writeln!(
                stream,
                "{{\"decision\":\"deny\",\"rule\":\"approvers must use the host socket\"}}"
            );
        }
        (ClientMessage::Exec { .. }, Role::Approver) => {
            let _ = writeln!(
                stream,
                "{{\"decision\":\"deny\",\"rule\":\"exec requests belong on the sandbox socket\"}}"
            );
        }
        (ClientMessage::Exec { argv, cwd }, Role::Exec) => {
            let reply = decide_exec(shared, &argv, &cwd);
            let _ = writeln!(
                stream,
                "{}",
                serde_json::to_string(&reply).unwrap_or_default()
            );
        }
    }
}

fn decide_exec(shared: &Arc<Shared>, argv: &[String], cwd: &str) -> ExecReply {
    let decision = shared.compiled.decide(&Request::Command { argv });
    let (outcome, rule) = match decision {
        Decision::Allow { rule } => ("allow", rule.unwrap_or_else(|| "default".into())),
        Decision::Deny { rule } => ("deny", rule),
        Decision::Ask { rule, prompt } => {
            shared.log.log(
                "approval.request",
                serde_json::json!({"prompt": prompt, "rule": rule, "argv": argv}),
            );
            let approved = ask(shared, &prompt, &rule);
            shared.log.log(
                "approval.response",
                serde_json::json!({"rule": rule, "approved": approved}),
            );
            (if approved { "allow" } else { "deny" }, rule)
        }
    };
    shared.log.log(
        "exec",
        serde_json::json!({"argv": argv, "cwd": cwd, "decision": outcome, "rule": rule}),
    );
    ExecReply {
        decision: outcome.to_string(),
        rule,
    }
}

/// Ask a human. Order: connected approver clients, then the terminal, each
/// only if the policy lists that transport. Timeout or no transport: deny.
fn ask(shared: &Arc<Shared>, prompt: &str, rule: &str) -> bool {
    if shared.no_ask {
        ui::warn(&format!("denied (--no-ask): {prompt} [{rule}]"));
        return false;
    }
    for t in &shared.transports {
        match t {
            Transport::Socket => {
                if let Some(answer) = ask_approvers(shared, prompt, rule) {
                    return answer;
                }
            }
            Transport::Tty => {
                if let Some(answer) = ask_tty(prompt, rule, shared.timeout) {
                    return answer;
                }
            }
        }
    }
    ui::warn(&format!("denied (no approver answered): {prompt} [{rule}]"));
    false
}

fn ask_approvers(shared: &Arc<Shared>, prompt: &str, rule: &str) -> Option<bool> {
    let id = {
        let mut g = shared.next_id.lock().ok()?;
        let id = *g;
        *g += 1;
        id
    };
    let mut approvers = shared.approvers.lock().ok()?;
    // Try each approver in turn; drop the ones that are gone.
    let i = 0;
    while i < approvers.len() {
        let msg = serde_json::to_string(&PromptMessage {
            id,
            prompt: prompt.into(),
            rule: rule.into(),
        })
        .ok()?;
        let ok = writeln!(approvers[i], "{msg}").is_ok();
        if !ok {
            approvers.remove(i);
            continue;
        }
        let _ = approvers[i].set_read_timeout(Some(shared.timeout));
        let mut line = String::new();
        let read = approvers[i]
            .try_clone()
            .ok()
            .and_then(|s| BufReader::new(s).read_line(&mut line).ok());
        match read {
            Some(n) if n > 0 => {
                if let Ok(a) = serde_json::from_str::<AnswerMessage>(&line) {
                    if a.id == id {
                        return Some(
                            a.answer.eq_ignore_ascii_case("y")
                                || a.answer.eq_ignore_ascii_case("yes"),
                        );
                    }
                }
                return Some(false);
            }
            _ => {
                approvers.remove(i);
            }
        }
    }
    None
}

fn ask_tty(prompt: &str, rule: &str, timeout: Duration) -> Option<bool> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    // Where the sandbox holds the terminal's foreground (macOS), take it
    // back for the prompt; a no-op on Linux.
    let _terminal = agentkeep_sandbox::PromptTerminal::take();
    let _ = write!(
        tty,
        "\r\n{} {prompt}\r\n  rule: {rule}\r\n  allow? [y/N] ({}s) ",
        ui::bold("[agentkeep]"),
        timeout.as_secs()
    );
    let _ = tty.flush();
    let (tx, rx) = mpsc::channel();
    let reader = tty.try_clone().ok()?;
    thread::spawn(move || {
        let mut line = String::new();
        // A read error (e.g. EIO for a background process) means the
        // terminal cannot answer; the next transport is tried, and with
        // none left the request is denied.
        let read = BufReader::new(reader).read_line(&mut line);
        let _ = tx.send(read.ok().map(|_| line));
    });
    let answer = rx.recv_timeout(timeout);
    if let Ok(None) = answer {
        let _ = writeln!(tty, "\r\n  terminal unavailable\r");
        return None;
    }
    if let Ok(Some(line)) = answer {
        let yes = matches!(line.trim(), "y" | "Y" | "yes" | "YES");
        let _ = writeln!(tty, "  {}\r", if yes { "allowed" } else { "denied" });
        Some(yes)
    } else {
        let _ = writeln!(tty, "\r\n  timed out: denied\r");
        Some(false)
    }
}

/// `agentkeep approve <socket>`: attach and answer prompts interactively.
pub fn approve_client(_globals: &Globals, args: &ApproveArgs) -> Result<ExitCode> {
    let mut stream = UnixStream::connect(&args.socket)
        .with_context(|| format!("connect {}", args.socket.display()))?;
    writeln!(
        stream,
        "{}",
        serde_json::to_string(&ClientMessage::Approver)?
    )?;
    eprintln!("agentkeep: attached; waiting for approval requests (Ctrl-C to detach)");
    let reader = BufReader::new(stream.try_clone()?);
    let stdin = std::io::stdin();
    for line in reader.lines() {
        let line = line?;
        let Ok(p) = serde_json::from_str::<PromptMessage>(&line) else {
            continue;
        };
        eprint!(
            "{} {}\n  rule: {}\n  allow? [y/N] ",
            ui::bold("[agentkeep]"),
            p.prompt,
            p.rule
        );
        let mut answer = String::new();
        stdin.lock().read_line(&mut answer)?;
        let yes = matches!(answer.trim(), "y" | "Y" | "yes" | "YES");
        let reply = AnswerMessage {
            id: p.id,
            answer: if yes { "y".into() } else { "n".into() },
        };
        writeln!(stream, "{}", serde_json::to_string(&reply)?)?;
    }
    Ok(ExitCode::SUCCESS)
}
