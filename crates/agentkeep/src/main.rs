//! `agentkeep`: run any agent with one command. It can only touch what you
//! allow, and you can see everything it did.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// Most of the CLI drives the Unix sandbox; on other platforms it is
// deliberately unreachable until their backends land.
#![cfg_attr(not(unix), allow(dead_code))]

#[cfg(unix)]
mod approval;
mod cli;
mod doctor;
mod load;
#[cfg(unix)]
mod netwire;
mod policy_cmd;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod shim;
mod ui;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

/// Exit status used by every command that is not implemented yet.
///
/// Deliberately not 0 (success) and not 1 (findings / policy denial) so that
/// a stub can never be mistaken for a real decision.
const EXIT_NOT_IMPLEMENTED: u8 = 70;

fn main() -> ExitCode {
    #[cfg(unix)]
    {
        let raw: Vec<String> = std::env::args().collect();

        // Started through a command shim inside a sandbox? Shims are
        // symlinks named after the command, on every Unix backend.
        if let Some(name) = raw
            .first()
            .and_then(|a| agentkeep_sandbox::invoked_as_shim(a))
        {
            return shim::main(&name, &raw[1..]);
        }

        // The Linux sandbox init process. Parsed by hand: it must not depend
        // on the full CLI, and its arguments are fds chosen by the supervisor.
        #[cfg(target_os = "linux")]
        if raw.get(1).map(String::as_str) == Some("__init") {
            let fd = |flag: &str| -> i32 {
                raw.iter()
                    .position(|a| a == flag)
                    .and_then(|i| raw.get(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(-1)
            };
            agentkeep_sandbox::linux::init::main(
                fd("--plan-fd"),
                fd("--sync-fd"),
                fd("--status-fd"),
            );
        }
    }

    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            ui::error(&format!("{err:#}"));
            ExitCode::from(2)
        }
    }
}

fn dispatch(cli: Cli) -> anyhow::Result<ExitCode> {
    let globals = cli::Globals {
        policy: cli.policy,
        verbose: cli.verbose,
        no_ask: cli.no_ask,
    };
    match cli.command {
        Command::Version => {
            print_version();
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(unix)]
        Command::Run(args) => run::run(&globals, &args),
        #[cfg(unix)]
        Command::Approve(args) => approval::approve_client(&globals, &args),
        #[cfg(not(unix))]
        Command::Run(_) | Command::Approve(_) => {
            ui::error(
                "no sandbox backend on this platform yet; Windows support runs through WSL2 and lands in Phase 2",
            );
            Ok(ExitCode::from(doctor::EXIT_NO_BACKEND))
        }
        Command::Policy(cmd) => policy_cmd::run(&globals, cmd),
        Command::Doctor(args) => doctor::run(args.json),
        other => {
            ui::error(&format!(
                "`{}` is not implemented yet (planned for {}). See PLAN.md.",
                other.name(),
                other.phase()
            ));
            Ok(ExitCode::from(EXIT_NOT_IMPLEMENTED))
        }
    }
}

fn print_version() {
    println!("agentkeep {}", env!("CARGO_PKG_VERSION"));
    println!("  policy   {}", agentkeep_policy::VERSION);
    println!("  sandbox  {}", agentkeep_sandbox::VERSION);
    println!("  proxy    {}", agentkeep_proxy::VERSION);
    println!("  mcp      {}", agentkeep_mcp::VERSION);
    println!("  scan     {}", agentkeep_scan::VERSION);
    println!("  audit    {}", agentkeep_audit::VERSION);
    println!("  tui      {}", agentkeep_tui::VERSION);
    println!("  common   {}", agentkeep_common::VERSION);
}
