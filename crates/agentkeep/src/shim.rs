//! Shim mode: agentkeep was started under another name through a symlink
//! placed first on `PATH` inside the sandbox. Ask the supervisor whether the
//! command may run, then hand over to the real binary.
//!
//! This is advisory (threat model C1, C2): a process can bypass it with an
//! absolute path. The filesystem and network layers are the real boundary.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::approval::{ClientMessage, ExecReply};

/// Exit code when the policy denies a command.
pub const EXIT_DENIED: u8 = 126;
/// Exit code when the real binary cannot be found.
pub const EXIT_NOT_FOUND: u8 = 127;

fn fail(msg: &str, code: u8) -> ExitCode {
    eprintln!("agentkeep: {msg}");
    ExitCode::from(code)
}

/// Find `name` on `PATH`, skipping the shim directory.
fn find_real(name: &str, shim_dir: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if shim_dir.is_some_and(|s| s == dir) {
            continue;
        }
        let candidate = dir.join(name);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            use std::os::unix::fs::PermissionsExt;
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                return Some(candidate);
            }
        }
    }
    None
}

/// Entry point for shim mode.
pub fn main(name: &str, args: &[String]) -> ExitCode {
    let mut full_argv = vec![name.to_string()];
    full_argv.extend(args.iter().cloned());
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Fail closed: no socket, no answer, no run.
    let Some(socket) = std::env::var_os("AGENTKEEP_SOCKET") else {
        return fail(
            "command shim active but AGENTKEEP_SOCKET is unset; refusing to run",
            EXIT_DENIED,
        );
    };
    let reply = (|| -> std::io::Result<ExecReply> {
        let mut stream = UnixStream::connect(&socket)?;
        stream.set_read_timeout(Some(Duration::from_mins(10)))?;
        let msg = serde_json::to_string(&ClientMessage::Exec {
            argv: full_argv.clone(),
            cwd,
        })?;
        writeln!(stream, "{msg}")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(&line)?)
    })();
    let reply = match reply {
        Ok(r) => r,
        Err(e) => {
            return fail(
                &format!("cannot reach the agentkeep supervisor ({e}); refusing to run `{name}`"),
                EXIT_DENIED,
            )
        }
    };
    if reply.decision != "allow" {
        return fail(
            &format!("`{}` denied by policy: {}", full_argv.join(" "), reply.rule),
            EXIT_DENIED,
        );
    }

    let shim_dir = std::env::var_os("AGENTKEEP_SHIM_DIR").map(PathBuf::from);
    let Some(real) = find_real(name, shim_dir.as_deref()) else {
        return fail(&format!("`{name}` not found on PATH"), EXIT_NOT_FOUND);
    };
    let err = std::process::Command::new(&real).args(args).exec();
    fail(&format!("exec {}: {err}", real.display()), EXIT_NOT_FOUND)
}
