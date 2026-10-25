//! `agentkeep`: run any agent with one command. It can only touch what you
//! allow, and you can see everything it did.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod approval;
mod cli;
mod load;
mod policy_cmd;
mod run;
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
    let raw: Vec<String> = std::env::args().collect();

    // Started through a command shim inside a sandbox?
    #[cfg(target_os = "linux")]
    if let Some(name) = raw
        .first()
        .and_then(|a| agentkeep_sandbox::linux::invoked_as_shim(a))
    {
        return shim::main(&name, &raw[1..]);
    }

    // The sandbox init process. Parsed by hand: it must not depend on the
    // full CLI, and its arguments are fds chosen by the supervisor.
    #[cfg(target_os = "linux")]
    if raw.get(1).map(String::as_str) == Some("__init") {
        let fd = |flag: &str| -> i32 {
            raw.iter()
                .position(|a| a == flag)
                .and_then(|i| raw.get(i + 1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(-1)
        };
        agentkeep_sandbox::linux::init::main(fd("--plan-fd"), fd("--sync-fd"), fd("--status-fd"));
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
        Command::Run(args) => run::run(&globals, &args),
        Command::Policy(cmd) => policy_cmd::run(&globals, cmd),
        Command::Approve(args) => approval::approve_client(&globals, &args),
        Command::Doctor => run::doctor(),
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
