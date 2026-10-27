//! PID 1 inside a container started by the container backend
//! (`agentkeep __container-init`).
//!
//! The runtime has already built the mount tree, the namespaces and its own
//! seccomp profile, and dropped every capability. This init adds what the
//! Linux backend's init adds on top of its own mounts: the proxy relay,
//! rlimits, `no_new_privs`, Landlock and agentkeep's seccomp deny-list, then
//! runs the command and reaps until it exits.
//!
//! It talks to the supervisor over the lifeline socket: one line, `READY`
//! or `ERR <reason>`, then the connection stays open for the life of the
//! session. When it closes (the supervisor exited, crashed or was killed)
//! init kills everything, so a container can never outlive its supervisor.

use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;

use rustix::process::{set_dumpable_behavior, DumpableBehavior};

use crate::linux::{init, landlock_rules, limits, relay, seccomp, sys};
use crate::plan::LaunchPlan;

use super::args::{LIFELINE, PLAN};

/// Exit code when the lifeline breaks: the supervisor is gone.
const LIFELINE_LOST: i32 = 137;

fn parse_abi(args: &[String]) -> u32 {
    args.iter()
        .position(|a| a == "--landlock-abi")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Entry point for `agentkeep __container-init`. Never returns.
pub fn main(args: &[String]) -> ! {
    // The command must start with default dispositions; ours go in after
    // it is spawned.
    sys::default_signal(libc::SIGINT);
    sys::default_signal(libc::SIGTERM);
    sys::default_signal(libc::SIGHUP);

    let mut lifeline = match UnixStream::connect(LIFELINE) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("agentkeep: container init cannot reach the supervisor at {LIFELINE}: {e}");
            sys::exit_now(init::SETUP_FAILED);
        }
    };
    let child = match setup_and_spawn(parse_abi(args)) {
        Ok(child) => child,
        Err(msg) => {
            let _ = writeln!(lifeline, "ERR {msg}");
            sys::exit_now(init::SETUP_FAILED);
        }
    };
    if writeln!(lifeline, "READY").is_err() {
        let _ = sys::kill(-1, libc::SIGKILL);
        sys::exit_now(LIFELINE_LOST);
    }
    let watch = std::thread::Builder::new()
        .name("agentkeep-lifeline".into())
        .spawn(move || {
            let mut buf = [0u8; 64];
            // The supervisor never writes; any return means it is gone.
            while matches!(lifeline.read(&mut buf), Ok(n) if n > 0) {}
            let _ = sys::kill(-1, libc::SIGKILL);
            sys::exit_now(LIFELINE_LOST);
        });
    if watch.is_err() {
        let _ = sys::kill(-1, libc::SIGKILL);
        sys::exit_now(init::SETUP_FAILED);
    }

    // With a TTY, Ctrl-C reaches the command through the terminal, as with
    // the Linux backend. Without one, the runtime CLI proxies the signals it
    // receives to PID 1 only, so they are forwarded from here.
    sys::record_signal(libc::SIGTERM);
    let forward: &[libc::c_int] = if std::io::stdin().is_terminal() {
        sys::ignore_signal(libc::SIGINT);
        sys::ignore_signal(libc::SIGHUP);
        &[libc::SIGTERM]
    } else {
        sys::record_signal(libc::SIGINT);
        sys::record_signal(libc::SIGHUP);
        &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP]
    };
    sys::exit_now(init::reap(child, forward))
}

fn setup_and_spawn(expected_landlock: u32) -> Result<std::process::Child, String> {
    let text = std::fs::read_to_string(PLAN).map_err(|e| format!("read {PLAN}: {e}"))?;
    let plan = LaunchPlan::from_json(&text).map_err(|e| e.to_string())?;

    // The command runs under the same uid as init. Not dumpable means it
    // cannot open /proc/1/mem or /proc/1/fd to reach into init, which holds
    // the lifeline and runs the relay outside the seccomp filter.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("set non-dumpable: {e}"))?;

    if let Some(proxy) = &plan.proxy {
        relay::start(proxy.port, proxy.sandbox_socket.clone())?;
    }

    // The supervisor cleared memory and pids from the plan when the
    // runtime's cgroup enforces them; whatever is left falls back to
    // rlimits, as in the Linux backend.
    limits::apply_rlimits(&plan.limits, true);

    // The runtime already dropped every capability; doing it again costs
    // nothing and does not depend on the runtime's configuration.
    sys::drop_all_capabilities().map_err(|e| format!("drop capabilities: {e}"))?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;

    if plan.landlock {
        // The probe claimed the host kernel's ABI; a runtime whose seccomp
        // profile hides Landlock must not turn that claim into a silent
        // no-op.
        let inside = landlock_rules::kernel_abi();
        if inside < expected_landlock {
            return Err(format!(
                "Landlock ABI {inside} inside the container, {expected_landlock} on the host: the runtime's seccomp profile blocks Landlock"
            ));
        }
        landlock_rules::apply(&plan)?;
    }
    if plan.seccomp {
        seccomp::apply()?;
    }
    init::spawn_command(&plan)
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_argument() {
        let a: Vec<String> = ["__container-init", "--landlock-abi", "4"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(super::parse_abi(&a), 4);
        assert_eq!(super::parse_abi(&a[..1]), 0);
    }
}
