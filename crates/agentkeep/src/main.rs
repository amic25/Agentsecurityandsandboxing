//! `agentkeep`: run any agent with one command. It can only touch what you
//! allow, and you can see everything it did.
//!
//! Phase 0 ships the command surface only. Each subcommand reports that it is
//! not implemented yet and exits with a distinct status so scripts never
//! mistake a stub for a successful run.

#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

/// Exit status used by every command that is not implemented yet.
///
/// It is deliberately not 0 (success) and not 1 (findings / policy denial) so
/// that a stub can never be mistaken for a real decision.
const EXIT_NOT_IMPLEMENTED: u8 = 70;

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Version => {
            print_version();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "agentkeep: `{}` is not implemented yet (planned for {}). See PLAN.md.",
                other.name(),
                other.phase()
            );
            ExitCode::from(EXIT_NOT_IMPLEMENTED)
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
